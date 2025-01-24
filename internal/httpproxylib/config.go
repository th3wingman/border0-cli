package httpproxylib

import (
	"fmt"
	"net/url"
)

type targetConfig struct {
	url        *url.URL
	hostHeader *string
}

func getTargetConfig(
	hostname string,
	port int,
	hostheader *string,
) (*targetConfig, error) {
	proto := "http"
	if port == 443 {
		proto = "https"
	}

	url, err := url.Parse(fmt.Sprintf("%s://%s:%d", proto, hostname, port))
	if err != nil {
		return nil, fmt.Errorf("failed to parse target url: %v", err)
	}

	return &targetConfig{
		url:        url,
		hostHeader: hostheader,
	}, nil
}
