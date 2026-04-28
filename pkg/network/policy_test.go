package network_test

import (
	"testing"

	"github.com/vamsiv/aegisbox/pkg/network"
)

func TestRestrictedPolicy_DenyByDefault(t *testing.T) {
	p := network.DefaultRestrictedPolicy()
	if p.Allows("api.openai.com", 443) {
		t.Error("restricted policy with no rules should deny all")
	}
}

func TestRestrictedPolicy_AllowExplicit(t *testing.T) {
	p := &network.Policy{
		Mode:  "restricted",
		Allow: []network.Rule{{Host: "api.openai.com", Ports: []int{443}}},
	}
	if !p.Allows("api.openai.com", 443) {
		t.Error("explicitly allowed host:port should be permitted")
	}
	if p.Allows("api.openai.com", 80) {
		t.Error("different port should still be denied")
	}
}

func TestOpenPolicy_AllowsAll(t *testing.T) {
	p := &network.Policy{Mode: "open"}
	if !p.Allows("anything.internal", 22) {
		t.Error("open policy should allow all connections")
	}
}

func TestIsolatedPolicy_DenyAll(t *testing.T) {
	p := &network.Policy{
		Mode:  "isolated",
		Allow: []network.Rule{{Host: "*", Ports: []int{0}}},
	}
	if p.Allows("127.0.0.1", 80) {
		t.Error("isolated policy should deny everything, even with wildcard rules")
	}
}

func TestCIDRRule(t *testing.T) {
	p := &network.Policy{
		Mode:  "restricted",
		Allow: []network.Rule{{Host: "10.0.0.0/8", Ports: []int{443}}},
	}
	if !p.Allows("10.1.2.3", 443) {
		t.Error("address inside CIDR should be allowed")
	}
	if p.Allows("192.168.1.1", 443) {
		t.Error("address outside CIDR should be denied")
	}
}
