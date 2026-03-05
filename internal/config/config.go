package config

import (
	"net"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

// Config holds the operator configuration.
type Config struct {
	// HCloudToken is the Hetzner Cloud API token.
	HCloudToken string

	// FirewallName is the name of the firewall to manage.
	FirewallName string

	// ClusterCIDRv4 is an optional IPv4 CIDR to always allow (e.g. Pod CIDR).
	ClusterCIDRv4 string

	// ClusterCIDRv6 is an optional IPv6 CIDR to always allow.
	ClusterCIDRv6 string

	// AllowSSHFrom restricts SSH access. Empty = no SSH rule. "0.0.0.0/0" = open.
	AllowSSHFrom []string

	// NodePortPublic controls whether NodePort range (30000-32767) is open to the internet.
	NodePortPublic bool

	// ReconcileInterval is how often to do a full reconciliation.
	ReconcileInterval time.Duration

	// LabelSelector filters which nodes to include (e.g. "node-role.kubernetes.io/control-plane").
	LabelSelector string

	// ServerNamePattern is a glob pattern (e.g. "platform-*") to discover Hetzner servers
	// via the API before they join the K8s cluster. Empty = disabled.
	ServerNamePattern string

	// DiscoveryInterval is how often to poll the Hetzner API for new servers
	// matching ServerNamePattern. Only used when ServerNamePattern is set.
	DiscoveryInterval time.Duration

	// LoadBalancerNames is a list of Hetzner Cloud Load Balancer names.
	// When set, HTTP/HTTPS (80/443) firewall rules are restricted to the
	// public IPs of these load balancers instead of 0.0.0.0/0.
	LoadBalancerNames []string
}

// PortRule defines a firewall port rule template.
type PortRule struct {
	Description string
	Direction   hcloud.FirewallRuleDirection
	Protocol    hcloud.FirewallRuleProtocol
	Port        string
	SourceType  SourceType // Determines which IPs populate the SourceIPs field
}

// SourceType determines how source IPs are resolved for a rule.
type SourceType int

const (
	// SourceClusterNodes uses all cluster node IPs.
	SourceClusterNodes SourceType = iota
	// SourceServerNodes uses only server/control-plane node IPs.
	SourceServerNodes
	// SourcePublic uses 0.0.0.0/0 and ::/0.
	SourcePublic
	// SourceLoadBalancers uses the public IPs of configured load balancers.
	// Falls back to SourcePublic when no load balancer IPs are available.
	SourceLoadBalancers
)

// RKE2CiliumRules returns the predefined port rules for an RKE2 + Cilium cluster.
func RKE2CiliumRules(nodePortPublic bool, useLoadBalancers bool) []PortRule {
	httpSource := SourcePublic
	if useLoadBalancers {
		httpSource = SourceLoadBalancers
	}

	rules := []PortRule{
		// RKE2 supervisor API - all nodes → server nodes
		{
			Description: "RKE2 supervisor API (node registration)",
			Direction:   hcloud.FirewallRuleDirectionIn,
			Protocol:    hcloud.FirewallRuleProtocolTCP,
			Port:        "9345",
			SourceType:  SourceClusterNodes,
		},
		// Kubernetes API - all nodes + external access
		{
			Description: "Kubernetes API server",
			Direction:   hcloud.FirewallRuleDirectionIn,
			Protocol:    hcloud.FirewallRuleProtocolTCP,
			Port:        "6443",
			SourceType:  SourceClusterNodes,
		},
		// VXLAN (Cilium tunnel) - all nodes
		{
			Description: "Cilium VXLAN overlay",
			Direction:   hcloud.FirewallRuleDirectionIn,
			Protocol:    hcloud.FirewallRuleProtocolUDP,
			Port:        "8472",
			SourceType:  SourceClusterNodes,
		},
		// kubelet metrics - all nodes
		{
			Description: "kubelet API",
			Direction:   hcloud.FirewallRuleDirectionIn,
			Protocol:    hcloud.FirewallRuleProtocolTCP,
			Port:        "10250",
			SourceType:  SourceClusterNodes,
		},
		// etcd client - server nodes only
		{
			Description: "etcd client requests",
			Direction:   hcloud.FirewallRuleDirectionIn,
			Protocol:    hcloud.FirewallRuleProtocolTCP,
			Port:        "2379",
			SourceType:  SourceServerNodes,
		},
		// etcd peer - server nodes only
		{
			Description: "etcd peer communication",
			Direction:   hcloud.FirewallRuleDirectionIn,
			Protocol:    hcloud.FirewallRuleProtocolTCP,
			Port:        "2380",
			SourceType:  SourceServerNodes,
		},
		// Cilium health checks
		{
			Description: "Cilium health checks",
			Direction:   hcloud.FirewallRuleDirectionIn,
			Protocol:    hcloud.FirewallRuleProtocolTCP,
			Port:        "4240",
			SourceType:  SourceClusterNodes,
		},
		// Cilium Hubble Relay
		{
			Description: "Hubble Relay",
			Direction:   hcloud.FirewallRuleDirectionIn,
			Protocol:    hcloud.FirewallRuleProtocolTCP,
			Port:        "4245",
			SourceType:  SourceClusterNodes,
		},
		// ICMP for both IPv4 and IPv6 (health probes, path MTU discovery)
		{
			Description: "ICMP (ping, PMTUD)",
			Direction:   hcloud.FirewallRuleDirectionIn,
			Protocol:    hcloud.FirewallRuleProtocolICMP,
			Port:        "",
			SourceType:  SourceClusterNodes,
		},
		// HTTP ingress - public or load balancers only
		{
			Description: "HTTP ingress",
			Direction:   hcloud.FirewallRuleDirectionIn,
			Protocol:    hcloud.FirewallRuleProtocolTCP,
			Port:        "80",
			SourceType:  httpSource,
		},
		// HTTPS ingress - public or load balancers only
		{
			Description: "HTTPS ingress",
			Direction:   hcloud.FirewallRuleDirectionIn,
			Protocol:    hcloud.FirewallRuleProtocolTCP,
			Port:        "443",
			SourceType:  httpSource,
		},
	}

	// NodePort range - public or cluster-only
	source := SourceClusterNodes
	if nodePortPublic {
		source = SourcePublic
	}
	rules = append(rules, PortRule{
		Description: "NodePort services (TCP)",
		Direction:   hcloud.FirewallRuleDirectionIn,
		Protocol:    hcloud.FirewallRuleProtocolTCP,
		Port:        "30000-32767",
		SourceType:  source,
	})
	rules = append(rules, PortRule{
		Description: "NodePort services (UDP)",
		Direction:   hcloud.FirewallRuleDirectionIn,
		Protocol:    hcloud.FirewallRuleProtocolUDP,
		Port:        "30000-32767",
		SourceType:  source,
	})

	return rules
}

// PublicNetworks returns the "any" source IPs for both IPv4 and IPv6.
func PublicNetworks() []net.IPNet {
	return []net.IPNet{
		{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},       // 0.0.0.0/0
		{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},      // ::/0
	}
}
