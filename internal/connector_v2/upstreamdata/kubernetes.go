package upstreamdata

import (
	"fmt"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-go/types/service"
)

func (u *UpstreamDataBuilder) buildUpstreamDataForKubernetesService(s *models.Socket, config *service.KubernetesServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got kubernetes service with no kubernetes service configuration")
	}

	// fetch applicable secrets from variable sources
	if config.KubernetesServiceType == service.KubectlExecTargetTypeStandard {
		config.StandardKubernetesServiceConfiguration.Token = u.fetchVariableFromSource(config.StandardKubernetesServiceConfiguration.Token)
		config.StandardKubernetesServiceConfiguration.ClientKeyData = u.fetchVariableFromSource(config.StandardKubernetesServiceConfiguration.ClientKeyData)
		config.StandardKubernetesServiceConfiguration.ClientCertificateData = u.fetchVariableFromSource(config.StandardKubernetesServiceConfiguration.ClientCertificateData)
	}

	s.ConnectorLocalData.KubernetesAPISettings = config
	return nil
}
