/*
Copyright Idea LCC. All Rights Reserved.

SPDX-License-Identifier: [Default license](LICENSE)
*/

package cryptocache

// CryptoCache is used for storing/retrieving crypto (certs and keys).
type CryptoCache interface {
	GetCrypto(key string) ([]byte, error)
	SetCrypto(key string, value []byte) error
}
