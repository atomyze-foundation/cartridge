package manager

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	vault "github.com/hashicorp/vault/api"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/atomyze-foundation/cartridge/cryptocache"
)

type Option func(c *VaultManager) error

// VaultManager handles VaultManager operations
type VaultManager struct {
	client          *vault.Client
	memcache        cryptocache.CryptoCache
	signingIdentity *VaultSigningIdentity
}

// NewVaultManager gets new instance of VaultManager
func NewVaultManager(mspID, userCert, address, token, namespace string) (*VaultManager, error) {
	config := &vault.Config{Address: address}
	client, err := vault.NewClient(config)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)

	manager := &VaultManager{client: client, memcache: cryptocache.NewMemCache()}
	if err = PullCrypto(manager, namespace, ""); err != nil {
		return nil, err
	}

	manager.signingIdentity, err = NewVaultSigningIdentity(mspID, userCert, manager)
	if err != nil {
		return nil, err
	}

	return manager, nil
}

func PullCrypto(manager *VaultManager, vaultPath string, keyname string) error {
	list, err := manager.client.Logical().List(vaultPath)
	if err != nil {
		return err
	}
	//nolint:nestif
	if list == nil {
		data, err := manager.client.Logical().Read(vaultPath)
		if err != nil {
			return err
		}

		// if Vault empty, return error
		if data == nil || data.Data["data"] == nil {
			return fmt.Errorf("path %s is empty", vaultPath)
		}

		cryptoAsString, ok := data.Data["data"].(string)
		if !ok {
			return fmt.Errorf("failed to cast value of key %s to string", vaultPath)
		}

		cryptoAsBytes, err := base64.StdEncoding.DecodeString(cryptoAsString)
		if err != nil && strings.Contains(err.Error(), "illegal base64 data at input byte 0") {
			cryptoAsBytes = []byte(cryptoAsString)
		} else if err != nil {
			return err
		}

		if strings.Contains(vaultPath, "/tls/") {
			parts := strings.Split(vaultPath, "/")
			if err := manager.memcache.SetCrypto(fmt.Sprintf("%s/%s/%s", parts[len(parts)-3], parts[len(parts)-2], keyname), cryptoAsBytes); err != nil { // username[@org]/tls/cryptoname
				return err
			}
		} else {
			if err := manager.memcache.SetCrypto(keyname, cryptoAsBytes); err != nil {
				return err
			}
		}

		return nil
	}

	keys, _ := list.Data["keys"].([]interface{})
	for _, key := range keys {
		keyname = key.(string) //nolint:forcetypeassert
		if err = PullCrypto(manager, filepath.Join(vaultPath, keyname), keyname); err != nil {
			return err
		}
	}

	return nil
}

func (v *VaultManager) Sign(digest []byte, ecdsaPrivateKey *ecdsa.PrivateKey, ecdsaPublicKey *ecdsa.PublicKey) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, ecdsaPrivateKey, digest)
	if err != nil {
		return nil, err
	}

	signature, err := utils.ToLowS(ecdsaPublicKey, s)
	if err != nil {
		return nil, err
	}

	return utils.MarshalECDSASignature(r, signature)
}

func (v *VaultManager) Verify(digest, signature []byte, ecdsaPublicKey *ecdsa.PublicKey) error {
	r, s, err := utils.UnmarshalECDSASignature(signature)
	if err != nil {
		return fmt.Errorf("failed unmashalling signature [%w]", err)
	}

	lowS, err := utils.IsLowS(ecdsaPublicKey, s)
	if err != nil {
		return err
	}

	if !lowS {
		return fmt.Errorf("invalid S. Must be smaller than half the order [%s][%s]", s, utils.GetCurveHalfOrdersAt(ecdsaPublicKey.Curve))
	}

	if ok := ecdsa.Verify(ecdsaPublicKey, digest, r, s); ok {
		return nil
	}

	return errors.New("invalid signature")
}

func (v *VaultManager) SigningIdentity() CartridgeSigningIdentity {
	return v.signingIdentity
}

func (v *VaultManager) Cache() cryptocache.CryptoCache {
	return v.memcache
}
