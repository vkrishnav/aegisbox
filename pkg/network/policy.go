package network

import "net"

// Rule allows traffic to a specific host/CIDR and optional port list.
// A zero port matches all ports.
type Rule struct {
	Host  string
	Ports []int
}

// Policy defines network access control for a container.
type Policy struct {
	Mode  string // "restricted" | "isolated" | "open"
	Allow []Rule
}

func DefaultRestrictedPolicy() *Policy {
	return &Policy{Mode: "restricted"}
}

// Allows reports whether the policy permits an outbound connection.
func (p *Policy) Allows(host string, port int) bool {
	switch p.Mode {
	case "open":
		return true
	case "isolated":
		return false
	}
	// "restricted" mode: deny unless an explicit rule matches.
	for _, rule := range p.Allow {
		if matchHost(rule.Host, host) && matchPort(rule.Ports, port) {
			return true
		}
	}
	return false
}

func matchHost(pattern, host string) bool {
	if pattern == "*" {
		return true
	}
	if _, cidr, err := net.ParseCIDR(pattern); err == nil {
		ip := net.ParseIP(host)
		return ip != nil && cidr.Contains(ip)
	}
	return pattern == host
}

func matchPort(ports []int, port int) bool {
	if len(ports) == 0 {
		return true // no port restriction = match all
	}
	for _, p := range ports {
		if p == 0 || p == port {
			return true
		}
	}
	return false
}
