package wgmgr

import (
	"net/netip"
	"strings"
	"time"

	"github.com/borderzero/border0-cli/internal/device/utils/dns"
	"go.uber.org/zap"
)

// determineBypassAddresses returns a list of addresses to set routes for
// (pointing to the default gateway). These are addresses that should never
// be talked to over WireGuard (always over the Internet).
func determineBypassAddresses(logger *zap.Logger, timeout time.Duration, relayURL string) []netip.Addr {
	inputs := []*dns.ResolutionInput{
		{
			Hostname: "stun.cloudflare.com",
			Defaults: []netip.Addr{
				netip.MustParseAddr("141.101.90.0"),     // stun.cloudflare.com A
				netip.MustParseAddr("2a06:98c1:3200::"), // stun.cloudflare.com AAAA
			},
		},
		{
			Hostname: "stun.l.google.com",
			Defaults: []netip.Addr{
				netip.MustParseAddr("74.125.250.129"),           // stun.cloudflare.com A
				netip.MustParseAddr("2001:4860:4864:5:8000::1"), // stun.cloudflare.com AAAA
			},
		},
		{
			Hostname: "api-prod-us-east-2.aws.border0.com",
			Defaults: []netip.Addr{
				netip.MustParseAddr("3.18.29.118"),                             // api-prod-us-east-2.aws.border0.com A
				netip.MustParseAddr("3.15.115.21"),                             // api-prod-us-east-2.aws.border0.com A
				netip.MustParseAddr("2600:1f16:1909:bd01:ccb4:5ab6:9e43:61c4"), // api-prod-us-east-2.aws.border0.com AAAA
				netip.MustParseAddr("2600:1f16:1909:bd00:27e1:7108:9988:ba39"), // api-prod-us-east-2.aws.border0.com AAAA
			},
		},
		{
			Hostname: "api-prod-eu-central-1.aws.border0.com",
			Defaults: []netip.Addr{
				netip.MustParseAddr("18.185.78.194"),                           // api-prod-eu-central-1.aws.border0.com A
				netip.MustParseAddr("18.195.28.176"),                           // api-prod-eu-central-1.aws.border0.com A
				netip.MustParseAddr("2a05:d014:167b:8801:451e:af32:18bd:73f1"), // api-prod-eu-central-1.aws.border0.com AAAA
				netip.MustParseAddr("2a05:d014:167b:8800:a859:4025:aaff:d24e"), // api-prod-eu-central-1.aws.border0.com AAAA
			},
		},
		{
			Hostname: "api-staging-us-east-2.aws.staging.border0.com",
			Defaults: []netip.Addr{
				netip.MustParseAddr("18.189.37.6"),                             // api-staging-us-east-2.aws.staging.border0.com A
				netip.MustParseAddr("18.190.69.81"),                            // api-staging-us-east-2.aws.staging.border0.com A
				netip.MustParseAddr("2600:1f16:11a9:8100:5df3:9067:de3d:9457"), // api-staging-us-east-2.aws.staging.border0.com AAAA
				netip.MustParseAddr("2600:1f16:11a9:8101:b01e:e112:72f:bfd9"),  // api-staging-us-east-2.aws.staging.border0.com AAAA
			},
		},
		{
			Hostname: "api-staging-eu-central-1.aws.staging.border0.com",
			Defaults: []netip.Addr{
				netip.MustParseAddr("3.68.121.220"),                            // api-staging-eu-central-1.aws.staging.border0.com A
				netip.MustParseAddr("18.157.110.11"),                           // api-staging-eu-central-1.aws.staging.border0.com A
				netip.MustParseAddr("2a05:d014:12ea:d001:4ed1:c892:ae31:203c"), // api-staging-eu-central-1.aws.staging.border0.com AAAA
				netip.MustParseAddr("2a05:d014:12ea:d000:66e5:6ac3:a84c:399"),  // api-staging-eu-central-1.aws.staging.border0.com AAAA
			},
		},
	}

	switch trimPrefixes(relayURL, "ws://", "wss://", "tcp://", "tls://") {
	case "glb.turtle.dev.border0.com":
		inputs = append(inputs, &dns.ResolutionInput{
			Hostname: "glb.turtle.dev.border0.com",
			Defaults: []netip.Addr{
				netip.MustParseAddr("172.66.0.162"),     // glb.turtle.dev.border0.com A
				netip.MustParseAddr("162.159.140.164"),  // glb.turtle.dev.border0.com A
				netip.MustParseAddr("2606:4700:7::a2"),  // glb.turtle.dev.border0.com AAAA
				netip.MustParseAddr("2a06:98c1:58::a2"), // glb.turtle.dev.border0.com AAAA
			},
		})
	case "glb.turtle.staging.border0.com":
		inputs = append(inputs, &dns.ResolutionInput{
			Hostname: "glb.turtle.staging.border0.com",
			Defaults: []netip.Addr{
				netip.MustParseAddr("162.159.140.164"),  // glb.turtle.staging.border0.com A
				netip.MustParseAddr("172.66.0.162"),     // glb.turtle.staging.border0.com A
				netip.MustParseAddr("2a06:98c1:58::a2"), // glb.turtle.staging.border0.com AAAA
				netip.MustParseAddr("2606:4700:7::a2"),  // glb.turtle.staging.border0.com AAAA
			},
		})
	case "glb.turtle.border0.com":
		inputs = append(inputs, &dns.ResolutionInput{
			Hostname: "glb.turtle.border0.com",
			Defaults: []netip.Addr{
				netip.MustParseAddr("162.159.140.164"),  // glb.turtle.border0.com A
				netip.MustParseAddr("172.66.0.162"),     // glb.turtle.border0.com A
				netip.MustParseAddr("2a06:98c1:58::a2"), // glb.turtle.border0.com AAAA
				netip.MustParseAddr("2606:4700:7::a2"),  // glb.turtle.border0.com AAAA
			},
		})
	case "relay.staging.border0.com":
		inputs = append(inputs, &dns.ResolutionInput{
			Hostname: "relay.staging.border0.com",
			Defaults: []netip.Addr{
				netip.MustParseAddr("75.2.47.126"),                             // relay.staging.border0.com A
				netip.MustParseAddr("99.83.233.29"),                            // relay.staging.border0.com A
				netip.MustParseAddr("2600:9000:a400:5294:255b:f824:ab72:37e7"), // relay.staging.border0.com AAAA
				netip.MustParseAddr("2600:9000:a50a:c7c:4da:83ff:12aa:834c"),   // relay.staging.border0.com AAAA
			},
		})
	case "relay.border0.com":
		inputs = append(inputs, &dns.ResolutionInput{
			Hostname: "relay.border0.com",
			Defaults: []netip.Addr{
				netip.MustParseAddr("76.223.117.131"),                         // relay.border0.com A
				netip.MustParseAddr("15.197.133.137"),                         // relay.border0.com A
				netip.MustParseAddr("2600:9000:a406:8740:12b3:135:b76:525d"),  // relay.border0.com AAAA
				netip.MustParseAddr("2600:9000:a71e:be1b:7c70:88f:e550:9d1a"), // relay.border0.com AAAA
			},
		})
	default:
		inputs = append(inputs, &dns.ResolutionInput{
			Hostname: trimPrefixes(relayURL, "ws://", "wss://", "tcp://", "tls://"),
		})
	}

	return dns.ResolveOrDefaults(logger, timeout, inputs...)
}

func trimPrefixes(input string, prefixes ...string) string {
	for _, prefix := range prefixes {
		if strings.HasPrefix(input, prefix) {
			return strings.TrimPrefix(input, prefix)
		}
	}
	return input
}
