/*
Copyright Idea LCC. All Rights Reserved.

SPDX-License-Identifier: [Default license](LICENSE)
*/

package cartridge

import (
	"github.com/atomyze-foundation/cartridge/connector/vaultconnector"
	"github.com/atomyze-foundation/cartridge/cryptocache"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/fab"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/msp"
)

// VaultConnector - VaultConnector is a struct that implements the core.ConfigProvider interface
type VaultConnector struct {
	coreBackend           []core.ConfigBackend
	ChannelConfigProvider func(name string) *fab.ChannelEndpointConfig
	ChannelPeersProvider  func(channel string) []fab.ChannelPeer
}

// NewVaultConnectProvider - NewVaultConnectProvider returns a new instance of VaultConnector
func NewVaultConnectProvider(coreBackend ...core.ConfigBackend) *VaultConnector {
	return &VaultConnector{
		coreBackend: coreBackend,
	}
}

// WithChannelConfigProvider - WithChannelConfigProvider sets the channel config provider
func (c *VaultConnector) WithChannelConfigProvider(channelConfigProvider func(name string) *fab.ChannelEndpointConfig) {
	c.ChannelConfigProvider = channelConfigProvider
}

// WithChannelPeersProvider - WithChannelPeersProvider sets the channel peers provider
func (c *VaultConnector) WithChannelPeersProvider(channelPeersProvider func(channel string) []fab.ChannelPeer) {
	c.ChannelPeersProvider = channelPeersProvider
}

// IdentityConfig - IdentityConfig returns the identity config
func (c *VaultConnector) IdentityConfig(cache cryptocache.CryptoCache) (msp.IdentityConfig, error) {
	return vaultconnector.IdentityConfigFromBackend(cache, c.coreBackend...)
}

// EndpointConfig - EndpointConfig returns the endpoint config
func (c *VaultConnector) EndpointConfig(cache cryptocache.CryptoCache) (fab.EndpointConfig, error) {
	return vaultconnector.EndpointConfigFromBackend(cache, c.ChannelConfigProvider, c.ChannelPeersProvider, c.coreBackend...)
}
