package plugin

import (
	"context"
	"fmt"

	"github.com/borderzero/border0-go/types/connector"
	"github.com/borderzero/discovery"
	"go.uber.org/zap"
)

type pluginImpl struct {
	ID     string
	logger *zap.Logger
	engine discovery.Engine
	cancel context.CancelFunc
}

// ensures pluginImpl implements Plugin at compile-time.
var _ Plugin = (*pluginImpl)(nil)

// NewPlugin returns a new plugin given a plugin configuration.
func NewPlugin(
	ctx context.Context,
	logger *zap.Logger,
	pluginId string,
	pluginType string,
	config *connector.PluginConfiguration,
) (Plugin, error) {
	logger = logger.With(zap.String("plugin_id", pluginId))
	switch pluginType {
	case connector.PluginTypeAwsEc2Discovery:
		return newAwsEc2DiscoveryPlugin(ctx, logger, pluginId, config.AwsEc2DiscoveryPluginConfiguration)
	case connector.PluginTypeAwsEcsDiscovery:
		return newAwsEcsDiscoveryPlugin(ctx, logger, pluginId, config.AwsEcsDiscoveryPluginConfiguration)
	case connector.PluginTypeAwsRdsDiscovery:
		return newAwsRdsDiscoveryPlugin(ctx, logger, pluginId, config.AwsRdsDiscoveryPluginConfiguration)
	case connector.PluginTypeKubernetesDiscovery:
		return newKubernetesDiscoveryPlugin(ctx, logger, pluginId, config.KubernetesDiscoveryPluginConfiguration)
	case connector.PluginTypeDockerDiscovery:
		return newDockerDiscoveryPlugin(ctx, logger, pluginId, config.DockerDiscoveryPluginConfiguration)
	case connector.PluginTypeNetworkDiscovery:
		return newNetworkDiscoveryPlugin(ctx, logger, pluginId, config.NetworkDiscoveryPluginConfiguration)
	default:
		return nil, fmt.Errorf("plugin type %s is not supported", pluginType)
	}
}

// Stop stops the plugin.
func (p *pluginImpl) Stop() error {
	if p.cancel != nil {
		p.cancel()
		return nil
	}
	return fmt.Errorf("cannot stop plugin not yet started (%s)", p.ID)
}

// Start starts the plugin.
func (p *pluginImpl) Start(ctx context.Context, results chan *PluginDiscoveryResults) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	p.cancel = cancel

	pluginResults := make(chan *discovery.Result)

	go p.engine.Run(ctx, pluginResults)

	for {
		select {
		case <-ctx.Done():
			return nil
		case result := <-pluginResults:
			p.logger.Debug("discovery result", zap.String("plugin_id", p.ID), zap.String("discoverer_id", result.Metadata.DiscovererId), zap.Int("resources", len(result.Resources)))
			if len(result.Errors) > 0 {
				p.logger.Warn("discovery errors", zap.String("plugin_id", p.ID), zap.String("discoverer_id", result.Metadata.DiscovererId), zap.Any("errors", result.Errors))
			}
			if len(result.Warnings) > 0 {
				p.logger.Info("discovery warnings", zap.String("plugin_id", p.ID), zap.String("discoverer_id", result.Metadata.DiscovererId), zap.Any("warnings", result.Warnings))
			}
			results <- &PluginDiscoveryResults{
				PluginID: p.ID,
				Result:   result,
			}
		}

	}
}
