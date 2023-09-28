package manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/atomyze-foundation/cartridge/cryptocache"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/sirupsen/logrus"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// SecretManager handles SecretManager operations
type SecretManager struct {
	client          *secretmanager.Client
	memcache        cryptocache.CryptoCache
	signingIdentity *VaultSigningIdentity
}

func encodeSecretName(secretName string) string {
	replacer := strings.NewReplacer("@", "____", "/", "___", ".", "__")
	return replacer.Replace(secretName)
}

func decodeSecretName(encodedSecretName string) string {
	replacer := strings.NewReplacer("____", "@", "___", "/", "__", ".")
	return replacer.Replace(encodedSecretName)
}

// NewSecretManager GetManager gets new instance of SecretManager
// userCryptoPath is used to resolve secrets for the current application (e.g. observer.atomyze.dev0.dlt.atomyze.ch)
func NewSecretManager(mspID, project, userCert, credsPath string) (*SecretManager, error) {
	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx, option.WithCredentialsFile(credsPath))
	if err != nil {
		return nil, err
	}

	manager := &SecretManager{client: client, memcache: cryptocache.NewMemCache()}
	t := time.Now()
	if err = manager.pullSecretCrypto(ctx, project, ""); err != nil {
		return nil, err
	}
	logrus.Infof("loading of cryptomaterials took %.2f seconds", time.Since(t).Seconds())

	manager.signingIdentity, err = NewVaultSigningIdentity(mspID, userCert, manager)
	if err != nil {
		return nil, err
	}

	return manager, nil
}

//nolint:funlen
func (sm *SecretManager) pullSecretCrypto(ctx context.Context, project string, keyName string) error {
	if keyName != "" {
		encodedSecretName := encodeSecretName(keyName)

		accessSecretVersionRequest := &secretmanagerpb.AccessSecretVersionRequest{
			Name: fmt.Sprintf("projects/%s/secrets/%s/versions/latest", project, encodedSecretName),
		}
		secretVersion, err := sm.client.AccessSecretVersion(ctx, accessSecretVersionRequest)
		if err != nil {
			return err
		}

		secretAsBytes, err := base64.StdEncoding.DecodeString(string(secretVersion.Payload.Data))
		if err != nil {
			return err
		}

		return sm.memcache.SetCrypto(keyName, secretAsBytes)
	}

	listSecretRequest := &secretmanagerpb.ListSecretsRequest{
		Parent: fmt.Sprintf("projects/%s", project),
	}

	secretIterator := sm.client.ListSecrets(ctx, listSecretRequest)
	for {
		secret, err := secretIterator.Next()
		if errors.Is(err, iterator.Done) {
			break
		}

		if err != nil {
			return fmt.Errorf("failed to list secret versions: %w", err)
		}

		accessSecretVersionRequest := &secretmanagerpb.AccessSecretVersionRequest{
			Name: secret.Name + "/versions/latest",
		}
		secretVersion, err := sm.client.AccessSecretVersion(ctx, accessSecretVersionRequest)
		if err != nil {
			if strings.Contains(err.Error(), "secretmanager.versions.access") || strings.Contains(err.Error(), "not found or has no versions") {
				continue
			}
			return err
		}

		decodedSecretName := decodeSecretName(secret.Name)

		if strings.Contains(decodedSecretName, "/tls/") {
			tlsIndex := strings.Index(decodedSecretName, "/tls/")
			secretName := decodedSecretName[tlsIndex-strings.Index(Reverse(decodedSecretName)[len(decodedSecretName)-tlsIndex:], "/"):]
			if err := sm.memcache.SetCrypto(secretName, secretVersion.Payload.Data); err != nil { // username@org/tls/cryptoname
				return err
			}
		} else {
			parts := strings.Split(decodedSecretName, "/")
			if err := sm.memcache.SetCrypto(parts[len(parts)-1], secretVersion.Payload.Data); err != nil {
				return err
			}
		}
	}

	return nil
}

// Reverse reverses a string
func Reverse(s string) (result string) {
	for _, v := range s {
		result = string(v) + result
	}
	return
}

// Sign signs digest using ecdsaPrivateKey
func (sm *SecretManager) Sign(digest []byte, ecdsaPrivateKey *ecdsa.PrivateKey, ecdsaPublicKey *ecdsa.PublicKey) ([]byte, error) {
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

// Verify verifies signature against digest using ecdsaPublicKey
func (sm *SecretManager) Verify(digest, signature []byte, ecdsaPublicKey *ecdsa.PublicKey) error {
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

// SigningIdentity returns signing identity
func (sm *SecretManager) SigningIdentity() CartridgeSigningIdentity {
	return sm.signingIdentity
}

// Cache returns cache
func (sm *SecretManager) Cache() cryptocache.CryptoCache {
	return sm.memcache
}
