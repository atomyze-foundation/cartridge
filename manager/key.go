package manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
)

// CartridgeKey is a core.Key wrapper for *ecdsa.PublicKey
type CartridgeKey struct {
	PrivKey *ecdsa.PrivateKey
	PubKey  *ecdsa.PublicKey
}

// Bytes converts this key to its byte representation.
func (k *CartridgeKey) Bytes() (raw []byte, err error) {
	raw, err = x509.MarshalPKIXPublicKey(k.PubKey)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling key [%w]", err)
	}
	return
}

// SKI returns the subject key identifier of this key.
func (k *CartridgeKey) SKI() (ski []byte) {
	if k.PubKey == nil {
		return nil
	}
	raw := elliptic.Marshal(k.PubKey.Curve, k.PubKey.X, k.PubKey.Y)
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

// Symmetric returns true if this key is a symmetric key, false otherwise.
func (k *CartridgeKey) Symmetric() bool {
	return false
}

// Private returns true if this key is a private key, false otherwise.
func (k *CartridgeKey) Private() bool {
	return false
}

// PublicKey returns the corresponding public key part of an asymmetric public/private key pair.
func (k *CartridgeKey) PublicKey() (core.Key, error) {
	return k, nil
}

func PEMToPrivateKey(raw []byte, pwd []byte) (interface{}, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("failed decoding PEM. Block must be different from nil [% x]", raw)
	}

	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck
		if len(pwd) == 0 {
			return nil, errors.New("encrypted Key. Need a password")
		}
		decrypted, err := x509.DecryptPEMBlock(block, pwd) //nolint:staticcheck
		if err != nil {
			return nil, fmt.Errorf("failed PEM decryption: [%w]", err)
		}
		key, err := derToPrivateKey(decrypted)
		if err != nil {
			return nil, err
		}
		return key, err
	}

	cert, err := derToPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, err
}

func derToPrivateKey(der []byte) (key interface{}, err error) {
	if key, err = x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err = x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key.(type) {
		case *ecdsa.PrivateKey:
			return
		default:
			return nil, errors.New("found unknown private key type in PKCS#8 wrapping")
		}
	}

	if key, err = x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("invalid key type. The DER must contain an ecdsa.PrivateKey")
}
