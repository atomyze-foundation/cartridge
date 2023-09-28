/*
Copyright Idea LCC. All Rights Reserved.

SPDX-License-Identifier: [Default license](LICENSE)
*/

package cartridge

import (
	"errors"

	"github.com/atomyze-foundation/cartridge/cryptocache"
	"github.com/atomyze-foundation/cartridge/manager"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

// Connector holds all necessary data (endpoints, certs) for connecting to HLF network.
type Connector struct {
	manager       manager.Manager
	provider      ConnectProvider
	cryptoStorage cryptocache.CryptoCache
}

// NewConnector creates Connector instance.
func NewConnector(manager manager.Manager, provider ConnectProvider) *Connector {
	return &Connector{manager: manager, provider: provider, cryptoStorage: manager.Cache()}
}

// Opts creates options array for subsequent pass to the fabsdk.New constructor.
func (c *Connector) Opts() ([]fabsdk.Option, error) {
	if c.cryptoStorage != nil {
		if c.provider == nil {
			return nil, errors.New("connect provider is empty")
		}
		identityConfig, err := c.provider.IdentityConfig(c.cryptoStorage)
		if err != nil {
			return nil, err
		}
		endpointConfig, err := c.provider.EndpointConfig(c.cryptoStorage)
		if err != nil {
			return nil, err
		}
		return []fabsdk.Option{fabsdk.WithCorePkg(NewCartridgeProviderFactory(c.manager)), fabsdk.WithIdentityConfig(identityConfig), fabsdk.WithEndpointConfig(endpointConfig)}, nil
	}
	return []fabsdk.Option{fabsdk.WithCorePkg(NewCartridgeProviderFactory(c.manager))}, nil
}
