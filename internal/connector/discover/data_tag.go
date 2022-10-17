package discover

import (
	"strings"

	"github.com/mitchellh/mapstructure"
)

type SocketDataTag struct {
	Port         string `mapstructure:"port"`
	Type         string `mapstructure:"type"`
	Group        string `mapstructure:"group"`
	Host         string `mapstructure:"host"`
	Name         string `mapstructure:"name"`
	UpstreamUser string `mapstructure:"upstream_user"`
	UpstreamPass string `mapstructure:"upstream_pass"`
	UpstreamType string `mapstructure:"upstream_type"`
}

// Parse the tag and transform it into a structured data called SocketDataTag
// example of tag = border0_ssh="port=22,type=ssh,group=allowed_users"
func parseLabels(tag string) SocketDataTag {
	labels := map[string]string{}
	for _, label := range strings.Split(tag, ",") {
		label = strings.TrimSpace(label)
		if strings.Contains(label, "=") {
			kv := strings.Split(label, "=")
			if len(kv) >= 2 {
				labels[kv[0]] = kv[1]
			}
		}
	}

	data := SocketDataTag{}
	mapstructure.Decode(labels, &data)

	return data
}
