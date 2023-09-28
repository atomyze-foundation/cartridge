/*
Copyright Idea LCC. All Rights Reserved.

SPDX-License-Identifier: [Default license](LICENSE)
*/

package cartridge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"sync"

	"github.com/atomyze-foundation/cartridge/manager"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric/bccsp/utils"
)

// NewCartridgeCryptoSuite returns cryptosuite adaptor for Signer
func NewCartridgeCryptoSuite(manager manager.Manager) core.CryptoSuite {
	return &CryptoSuite{manager: manager, crypto: &Crypto{crypto: make(map[string]core.Key)}}
}

// CryptoSuite provides a wrapper of Signer
type CryptoSuite struct {
	manager manager.Manager
	crypto  *Crypto
}

// Crypto stores mapping <keyname string : cryptovalue core.Key>
type Crypto struct {
	crypto map[string]core.Key
	sync.RWMutex
}

// Get retrieves crypto for key.
func (c *Crypto) Get(key string) (core.Key, error) {
	c.RLock()
	value, ok := c.crypto[key]
	c.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no crypto for key %s", key)
	}
	return value, nil
}

// Set sets crypto for key.
func (c *Crypto) Set(key string, value core.Key) error {
	c.Lock()
	c.crypto[key] = value
	c.Unlock()
	return nil
}

// KeyGen generate private/public key pair
func (c *CryptoSuite) KeyGen(_ core.KeyGenOpts) (k core.Key, err error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader) // this generates a public & private key pair
	if err != nil {
		return nil, err
	}
	return &manager.CartridgeKey{
		PrivKey: privateKey,
		PubKey:  &privateKey.PublicKey,
	}, nil
}

// KeyImport imports new key to CryptoSuite key store
func (c *CryptoSuite) KeyImport(raw interface{}, _ core.KeyImportOpts) (k core.Key, err error) {
	switch cert := raw.(type) {
	case *x509.Certificate:
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("invalid key type, it must be ECDSA Public Key")
		}
		pk := &manager.CartridgeKey{PubKey: pubKey}
		err = c.crypto.Set(hex.EncodeToString(pk.SKI()), pk)
		if err != nil {
			return nil, err
		}
		return pk, nil
	case *ecdsa.PublicKey:
		pk := &manager.CartridgeKey{PubKey: raw.(*ecdsa.PublicKey)} //nolint:forcetypeassert
		err = c.crypto.Set(hex.EncodeToString(pk.SKI()), pk)
		if err != nil {
			return nil, err
		}
		return pk, nil
	default:
		return nil, errors.New("unknown key type")
	}
}

// GetKey gets a key from CryptoSuite key store
func (c *CryptoSuite) GetKey(ski []byte) (core.Key, error) {
	key, err := c.crypto.Get(hex.EncodeToString(ski))
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Hash returns hash og some data using CryptoSuite hash
func (c *CryptoSuite) Hash(msg []byte, opts core.HashOpts) (hash []byte, err error) {
	h, err := c.GetHash(opts)
	if err != nil {
		return nil, err
	}
	h.Reset()
	h.Write(msg)
	defer h.Reset()

	return h.Sum(nil), nil
}

// GetHash returns CryptoSuite hash
func (c *CryptoSuite) GetHash(_ core.HashOpts) (h hash.Hash, err error) {
	return sha256.New(), nil
}

// Sign uses Manager to sign the digest
func (c *CryptoSuite) Sign(k core.Key, digest []byte, _ core.SignerOpts) (signature []byte, err error) {
	switch key := k.(type) {
	case *manager.CartridgeKey:
		sig, err := c.manager.Sign(digest, key.PrivKey, key.PubKey)
		if err != nil {
			return nil, err
		}
		sigLowS, err := utils.SignatureToLowS(key.PubKey, sig)
		if err != nil {
			return nil, err
		}
		signature = sigLowS
		return signature, err
	default:
		return nil, errors.New("invalid key type")
	}
}

// Verify verifies if signature is created using provided key
func (c *CryptoSuite) Verify(k core.Key, signature, digest []byte, _ core.SignerOpts) (valid bool, err error) {
	switch key := k.(type) {
	case *manager.CartridgeKey:
		r, s, err := utils.UnmarshalECDSASignature(signature)
		if err != nil {
			return false, fmt.Errorf("failed unmashalling signature [%w]", err)
		}
		return ecdsa.Verify(key.PubKey, digest, r, s), nil
	default:
		return false, errors.New("invalid key type")
	}
}
