/*
Copyright Idea LCC. All Rights Reserved.

SPDX-License-Identifier: [Default license](LICENSE)
*/

package cryptocache

import (
	"fmt"
	"sync"
)

// MemCache is an in-memory implementation of the CryptoCache interface.
type MemCache struct {
	crypto map[string][]byte // crypto stores mapping <keyname string : cryptovalue interface{}>
	sync.RWMutex
}

// NewMemCache creates MemCache instance and returns pointer to it.
func NewMemCache() *MemCache {
	return &MemCache{crypto: make(map[string][]byte)}
}

// GetCrypto retrieves crypto from in-memory storage.
func (m *MemCache) GetCrypto(key string) ([]byte, error) {
	m.RLock()
	value, ok := m.crypto[key]
	m.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no crypto for key %s", key)
	}
	return value, nil
}

// SetCrypto saves crypto to the in-memory storage.
func (m *MemCache) SetCrypto(key string, value []byte) error {
	m.Lock()
	m.crypto[key] = value
	m.Unlock()
	return nil
}
