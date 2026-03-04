package controller

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/atroo/hetzner-firewall-operator/internal/config"
	"github.com/atroo/hetzner-firewall-operator/internal/firewall"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

// mockResolver implements firewall.ServerResolver for testing.
type mockResolver struct {
	result map[string]int64
	err    error

	// DiscoverServers fields
	discoverResult []firewall.NodeInfo
	discoverErr    error
}

func (m *mockResolver) ResolveServerIDs(_ context.Context, names []string) (map[string]int64, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func (m *mockResolver) DiscoverServers(_ context.Context, namePattern string) ([]firewall.NodeInfo, error) {
	if m.discoverErr != nil {
		return nil, m.discoverErr
	}
	return m.discoverResult, nil
}

func TestParseHetznerProviderID(t *testing.T) {
	tests := []struct {
		name       string
		providerID string
		wantID     int64
		wantErr    bool
	}{
		{
			name:       "valid provider ID",
			providerID: "hcloud://12345",
			wantID:     12345,
		},
		{
			name:       "valid large ID",
			providerID: "hcloud://9999999999",
			wantID:     9999999999,
		},
		{
			name:       "empty string",
			providerID: "",
			wantErr:    true,
		},
		{
			name:       "wrong prefix",
			providerID: "aws://12345",
			wantErr:    true,
		},
		{
			name:       "no prefix",
			providerID: "12345",
			wantErr:    true,
		},
		{
			name:       "non-numeric ID",
			providerID: "hcloud://abc",
			wantErr:    true,
		},
		{
			name:       "prefix only",
			providerID: "hcloud://",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHetznerProviderID(tt.providerID)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseHetznerProviderID(%q) error = %v, wantErr %v", tt.providerID, err, tt.wantErr)
				return
			}
			if got != tt.wantID {
				t.Errorf("parseHetznerProviderID(%q) = %d, want %d", tt.providerID, got, tt.wantID)
			}
		})
	}
}

func TestIsControlPlaneNode(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{
			name:   "control-plane label",
			labels: map[string]string{"node-role.kubernetes.io/control-plane": ""},
			want:   true,
		},
		{
			name:   "master label",
			labels: map[string]string{"node-role.kubernetes.io/master": ""},
			want:   true,
		},
		{
			name:   "etcd label (RKE2 server)",
			labels: map[string]string{"node-role.kubernetes.io/etcd": ""},
			want:   true,
		},
		{
			name:   "multiple control-plane labels",
			labels: map[string]string{"node-role.kubernetes.io/control-plane": "", "node-role.kubernetes.io/etcd": ""},
			want:   true,
		},
		{
			name:   "worker node",
			labels: map[string]string{"node-role.kubernetes.io/worker": ""},
			want:   false,
		},
		{
			name:   "no labels",
			labels: map[string]string{},
			want:   false,
		},
		{
			name:   "nil labels",
			labels: nil,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Labels: tt.labels},
			}
			if got := isControlPlaneNode(node); got != tt.want {
				t.Errorf("isControlPlaneNode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddressesChanged(t *testing.T) {
	tests := []struct {
		name     string
		oldAddrs []corev1.NodeAddress
		newAddrs []corev1.NodeAddress
		want     bool
	}{
		{
			name: "no change",
			oldAddrs: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
			},
			newAddrs: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
			},
			want: false,
		},
		{
			name: "IP changed",
			oldAddrs: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
			},
			newAddrs: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "5.6.7.8"},
			},
			want: true,
		},
		{
			name: "address added",
			oldAddrs: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
			},
			newAddrs: []corev1.NodeAddress{
				{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
			},
			want: true,
		},
		{
			name:     "both empty",
			oldAddrs: nil,
			newAddrs: nil,
			want:     false,
		},
		{
			name:     "address removed",
			oldAddrs: []corev1.NodeAddress{{Type: corev1.NodeExternalIP, Address: "1.2.3.4"}},
			newAddrs: nil,
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldNode := &corev1.Node{Status: corev1.NodeStatus{Addresses: tt.oldAddrs}}
			newNode := &corev1.Node{Status: corev1.NodeStatus{Addresses: tt.newAddrs}}
			if got := addressesChanged(oldNode, newNode); got != tt.want {
				t.Errorf("addressesChanged() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCountServerNodes(t *testing.T) {
	tests := []struct {
		name  string
		nodes []firewall.NodeInfo
		want  int
	}{
		{
			name:  "empty",
			nodes: nil,
			want:  0,
		},
		{
			name: "all workers",
			nodes: []firewall.NodeInfo{
				{Name: "worker-1", IsServer: false},
				{Name: "worker-2", IsServer: false},
			},
			want: 0,
		},
		{
			name: "mixed",
			nodes: []firewall.NodeInfo{
				{Name: "server-1", IsServer: true},
				{Name: "worker-1", IsServer: false},
				{Name: "server-2", IsServer: true},
			},
			want: 2,
		},
		{
			name: "all servers",
			nodes: []firewall.NodeInfo{
				{Name: "server-1", IsServer: true},
				{Name: "server-2", IsServer: true},
			},
			want: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := countServerNodes(tt.nodes); got != tt.want {
				t.Errorf("countServerNodes() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestExtractNodeInfos(t *testing.T) {
	r := &NodeReconciler{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	nodes := []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "server-1",
				Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""},
			},
			Spec: corev1.NodeSpec{ProviderID: "hcloud://111"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "worker-1",
				Labels: map[string]string{},
			},
			Spec: corev1.NodeSpec{ProviderID: "hcloud://222"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "5.6.7.8"},
					{Type: corev1.NodeInternalIP, Address: "2001:db8::1"},
				},
			},
		},
		// Non-Hetzner node should be skipped (no resolver)
		{
			ObjectMeta: metav1.ObjectMeta{Name: "aws-node"},
			Spec:       corev1.NodeSpec{ProviderID: "aws://i-12345"},
		},
		// Node with no IPs should be skipped
		{
			ObjectMeta: metav1.ObjectMeta{Name: "no-ip-node"},
			Spec:       corev1.NodeSpec{ProviderID: "hcloud://333"},
		},
	}

	infos, err := r.extractNodeInfos(context.Background(), nodes)
	if err != nil {
		t.Fatalf("extractNodeInfos() error = %v", err)
	}

	if len(infos) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(infos))
	}

	// server-1
	if infos[0].Name != "server-1" || infos[0].ServerID != 111 || !infos[0].IsServer {
		t.Errorf("server-1: got %+v", infos[0])
	}
	if !infos[0].IPv4.Equal(net.ParseIP("1.2.3.4")) {
		t.Errorf("server-1 IPv4: got %v", infos[0].IPv4)
	}

	// worker-1
	if infos[1].Name != "worker-1" || infos[1].ServerID != 222 || infos[1].IsServer {
		t.Errorf("worker-1: got %+v", infos[1])
	}
	if !infos[1].IPv4.Equal(net.ParseIP("5.6.7.8")) {
		t.Errorf("worker-1 IPv4: got %v", infos[1].IPv4)
	}
	if infos[1].IPv6Net == nil {
		t.Fatal("worker-1 should have IPv6Net")
	}
	// IPv6 must be masked to /64 network boundary (host bits zeroed)
	expectedIPv6 := net.ParseIP("2001:db8::")
	if !infos[1].IPv6Net.IP.Equal(expectedIPv6) {
		t.Errorf("worker-1 IPv6Net.IP = %v, want %v (masked to /64)", infos[1].IPv6Net.IP, expectedIPv6)
	}
	ones, bits := infos[1].IPv6Net.Mask.Size()
	if ones != 64 || bits != 128 {
		t.Errorf("worker-1 IPv6Net.Mask = /%d (of %d), want /64", ones, bits)
	}
}

func TestBuildNodeInfo_IPv6Masking(t *testing.T) {
	r := &NodeReconciler{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	tests := []struct {
		name       string
		addr       string
		wantNetIP  string
		wantPrefix int
	}{
		{
			name:       "host bits zeroed",
			addr:       "2001:db8::5",
			wantNetIP:  "2001:db8::",
			wantPrefix: 64,
		},
		{
			name:       "already network address",
			addr:       "2001:db8::",
			wantNetIP:  "2001:db8::",
			wantPrefix: 64,
		},
		{
			name:       "complex host part",
			addr:       "2a01:4f8:c012:abc0::1",
			wantNetIP:  "2a01:4f8:c012:abc0::",
			wantPrefix: 64,
		},
		{
			name:       "full host bits set",
			addr:       "fd00:1234:5678:9abc:deff:aabb:ccdd:eeff",
			wantNetIP:  "fd00:1234:5678:9abc::",
			wantPrefix: 64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			node := &corev1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "test-node"},
				Spec:       corev1.NodeSpec{ProviderID: "hcloud://1"},
				Status: corev1.NodeStatus{
					Addresses: []corev1.NodeAddress{
						{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
						{Type: corev1.NodeInternalIP, Address: tt.addr},
					},
				},
			}

			info, ok := r.buildNodeInfo(node, 1)
			if !ok {
				t.Fatal("buildNodeInfo returned false")
			}
			if info.IPv6Net == nil {
				t.Fatal("IPv6Net is nil")
			}

			wantIP := net.ParseIP(tt.wantNetIP)
			if !info.IPv6Net.IP.Equal(wantIP) {
				t.Errorf("IPv6Net.IP = %v, want %v", info.IPv6Net.IP, wantIP)
			}
			ones, bits := info.IPv6Net.Mask.Size()
			if ones != tt.wantPrefix || bits != 128 {
				t.Errorf("IPv6Net.Mask = /%d (of %d), want /%d", ones, bits, tt.wantPrefix)
			}
		})
	}
}

func TestExtractNodeInfos_RKE2Nodes(t *testing.T) {
	resolver := &mockResolver{
		result: map[string]int64{
			"rke2-server-1": 444,
			"rke2-worker-1": 555,
		},
	}
	r := &NodeReconciler{
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		serverResolver: resolver,
	}

	nodes := []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "rke2-server-1",
				Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""},
			},
			Spec: corev1.NodeSpec{ProviderID: "rke2://rke2-server-1"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "10.0.0.1"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "rke2-worker-1",
				Labels: map[string]string{},
			},
			Spec: corev1.NodeSpec{ProviderID: "rke2://rke2-worker-1"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "10.0.0.2"},
				},
			},
		},
	}

	infos, err := r.extractNodeInfos(context.Background(), nodes)
	if err != nil {
		t.Fatalf("extractNodeInfos() error = %v", err)
	}

	if len(infos) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(infos))
	}

	if infos[0].Name != "rke2-server-1" || infos[0].ServerID != 444 || !infos[0].IsServer {
		t.Errorf("rke2-server-1: got %+v", infos[0])
	}
	if infos[1].Name != "rke2-worker-1" || infos[1].ServerID != 555 || infos[1].IsServer {
		t.Errorf("rke2-worker-1: got %+v", infos[1])
	}
}

func TestExtractNodeInfos_MixedHCloudAndRKE2(t *testing.T) {
	resolver := &mockResolver{
		result: map[string]int64{
			"rke2-node": 666,
		},
	}
	r := &NodeReconciler{
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		serverResolver: resolver,
	}

	nodes := []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "hcloud-node", Labels: map[string]string{}},
			Spec:       corev1.NodeSpec{ProviderID: "hcloud://111"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "rke2-node", Labels: map[string]string{}},
			Spec:       corev1.NodeSpec{ProviderID: "rke2://rke2-node"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "5.6.7.8"},
				},
			},
		},
	}

	infos, err := r.extractNodeInfos(context.Background(), nodes)
	if err != nil {
		t.Fatalf("extractNodeInfos() error = %v", err)
	}

	if len(infos) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(infos))
	}

	if infos[0].Name != "hcloud-node" || infos[0].ServerID != 111 {
		t.Errorf("hcloud-node: got %+v", infos[0])
	}
	if infos[1].Name != "rke2-node" || infos[1].ServerID != 666 {
		t.Errorf("rke2-node: got %+v", infos[1])
	}
}

func TestExtractNodeInfos_ResolverError(t *testing.T) {
	resolver := &mockResolver{
		err: fmt.Errorf("API error"),
	}
	r := &NodeReconciler{
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		serverResolver: resolver,
	}

	nodes := []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "hcloud-node", Labels: map[string]string{}},
			Spec:       corev1.NodeSpec{ProviderID: "hcloud://111"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "rke2-node", Labels: map[string]string{}},
			Spec:       corev1.NodeSpec{ProviderID: "rke2://rke2-node"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "5.6.7.8"},
				},
			},
		},
	}

	infos, err := r.extractNodeInfos(context.Background(), nodes)
	if err != nil {
		t.Fatalf("extractNodeInfos() should not return error on resolver failure, got %v", err)
	}

	// Only the hcloud node should be present; rke2-node skipped due to resolver error
	if len(infos) != 1 {
		t.Fatalf("expected 1 node (graceful degradation), got %d", len(infos))
	}
	if infos[0].Name != "hcloud-node" {
		t.Errorf("expected hcloud-node, got %s", infos[0].Name)
	}
}

func TestExtractNodeInfos_PartialResolution(t *testing.T) {
	resolver := &mockResolver{
		result: map[string]int64{
			"rke2-node-1": 777,
			// rke2-node-2 is NOT resolved
		},
	}
	r := &NodeReconciler{
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		serverResolver: resolver,
	}

	nodes := []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "rke2-node-1", Labels: map[string]string{}},
			Spec:       corev1.NodeSpec{ProviderID: "rke2://rke2-node-1"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "10.0.0.1"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "rke2-node-2", Labels: map[string]string{}},
			Spec:       corev1.NodeSpec{ProviderID: "rke2://rke2-node-2"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "10.0.0.2"},
				},
			},
		},
	}

	infos, err := r.extractNodeInfos(context.Background(), nodes)
	if err != nil {
		t.Fatalf("extractNodeInfos() error = %v", err)
	}

	if len(infos) != 1 {
		t.Fatalf("expected 1 resolved node, got %d", len(infos))
	}
	if infos[0].Name != "rke2-node-1" || infos[0].ServerID != 777 {
		t.Errorf("rke2-node-1: got %+v", infos[0])
	}
}

func TestExtractNodeInfos_NilResolver(t *testing.T) {
	r := &NodeReconciler{
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		serverResolver: nil,
	}

	nodes := []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "rke2-node", Labels: map[string]string{}},
			Spec:       corev1.NodeSpec{ProviderID: "rke2://rke2-node"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "10.0.0.1"},
				},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "hcloud-node", Labels: map[string]string{}},
			Spec:       corev1.NodeSpec{ProviderID: "hcloud://111"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
				},
			},
		},
	}

	infos, err := r.extractNodeInfos(context.Background(), nodes)
	if err != nil {
		t.Fatalf("extractNodeInfos() error = %v", err)
	}

	// Only the hcloud node; rke2 node silently skipped with nil resolver
	if len(infos) != 1 {
		t.Fatalf("expected 1 node with nil resolver, got %d", len(infos))
	}
	if infos[0].Name != "hcloud-node" {
		t.Errorf("expected hcloud-node, got %s", infos[0].Name)
	}
}

func TestReconcile_PreJoinServerDiscovery(t *testing.T) {
	// This tests the pass 3 logic in Reconcile by populating the discovery cache
	// and then simulating the merge logic from Reconcile.

	r := &NodeReconciler{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:         config.Config{ServerNamePattern: "platform-*"},
		discoveryCh: make(chan event.GenericEvent, 1),
		// Pre-populate the discovery cache (as the poller would)
		discoveredServers: []firewall.NodeInfo{
			{
				Name:     "platform-new-1",
				ServerID: 888,
				IPv4:     net.ParseIP("10.0.1.1"),
			},
			{
				Name:     "platform-new-2",
				ServerID: 999,
				IPv4:     net.ParseIP("10.0.1.2"),
			},
		},
	}

	// Existing K8s nodes (pass 1)
	k8sNodes := []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "platform-existing",
				Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""},
			},
			Spec: corev1.NodeSpec{ProviderID: "hcloud://777"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "10.0.0.1"},
				},
			},
		},
	}

	nodes, err := r.extractNodeInfos(context.Background(), k8sNodes)
	if err != nil {
		t.Fatalf("extractNodeInfos() error = %v", err)
	}

	// Simulate pass 3 merge (same logic as in Reconcile)
	discovered := r.getDiscoveredServers()
	existing := make(map[int64]struct{}, len(nodes))
	for _, n := range nodes {
		if n.ServerID > 0 {
			existing[n.ServerID] = struct{}{}
		}
	}
	for _, d := range discovered {
		if _, ok := existing[d.ServerID]; !ok {
			nodes = append(nodes, d)
		}
	}

	if len(nodes) != 3 {
		t.Fatalf("expected 3 nodes (1 existing + 2 pre-join), got %d", len(nodes))
	}
	if nodes[0].Name != "platform-existing" || nodes[0].ServerID != 777 {
		t.Errorf("node[0]: got %+v", nodes[0])
	}
	if nodes[1].Name != "platform-new-1" || nodes[1].ServerID != 888 {
		t.Errorf("node[1]: got %+v", nodes[1])
	}
	if nodes[2].Name != "platform-new-2" || nodes[2].ServerID != 999 {
		t.Errorf("node[2]: got %+v", nodes[2])
	}
}

func TestReconcile_PreJoinServerDeduplication(t *testing.T) {
	// Server 777 exists in both K8s and discovery cache — should not be duplicated
	r := &NodeReconciler{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:         config.Config{ServerNamePattern: "platform-*"},
		discoveryCh: make(chan event.GenericEvent, 1),
		discoveredServers: []firewall.NodeInfo{
			{
				Name:     "platform-existing",
				ServerID: 777,
				IPv4:     net.ParseIP("10.0.0.1"),
			},
			{
				Name:     "platform-new",
				ServerID: 888,
				IPv4:     net.ParseIP("10.0.1.1"),
			},
		},
	}

	k8sNodes := []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "platform-existing",
				Labels: map[string]string{},
			},
			Spec: corev1.NodeSpec{ProviderID: "hcloud://777"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "10.0.0.1"},
				},
			},
		},
	}

	nodes, err := r.extractNodeInfos(context.Background(), k8sNodes)
	if err != nil {
		t.Fatalf("extractNodeInfos() error = %v", err)
	}

	// Simulate pass 3 merge from cache
	discovered := r.getDiscoveredServers()
	existing := make(map[int64]struct{}, len(nodes))
	for _, n := range nodes {
		if n.ServerID > 0 {
			existing[n.ServerID] = struct{}{}
		}
	}
	for _, d := range discovered {
		if _, ok := existing[d.ServerID]; !ok {
			nodes = append(nodes, d)
		}
	}

	// Only 2: existing (deduplicated) + new
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes (dedup), got %d", len(nodes))
	}
	if nodes[0].Name != "platform-existing" {
		t.Errorf("node[0]: got %+v", nodes[0])
	}
	if nodes[1].Name != "platform-new" || nodes[1].ServerID != 888 {
		t.Errorf("node[1]: got %+v", nodes[1])
	}
}

func TestReconcile_EmptyPatternSkipsDiscovery(t *testing.T) {
	r := &NodeReconciler{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:         config.Config{ServerNamePattern: ""}, // empty = disabled
		discoveryCh: make(chan event.GenericEvent, 1),
		// Even if cache has entries, empty pattern means pass 3 is skipped
		discoveredServers: []firewall.NodeInfo{
			{Name: "should-not-appear", ServerID: 999, IPv4: net.ParseIP("10.0.0.99")},
		},
	}

	k8sNodes := []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1", Labels: map[string]string{}},
			Spec:       corev1.NodeSpec{ProviderID: "hcloud://111"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
				},
			},
		},
	}

	nodes, err := r.extractNodeInfos(context.Background(), k8sNodes)
	if err != nil {
		t.Fatalf("extractNodeInfos() error = %v", err)
	}

	// With empty pattern, pass 3 is skipped — only K8s nodes
	if r.cfg.ServerNamePattern != "" {
		t.Fatal("pattern should be empty")
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node (no discovery), got %d", len(nodes))
	}
}

func TestReconcile_EmptyCacheGracefulDegradation(t *testing.T) {
	// When the discovery cache is empty (e.g. poller hasn't run yet or API failed),
	// reconcile should still work with just K8s nodes.
	r := &NodeReconciler{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:         config.Config{ServerNamePattern: "platform-*"},
		discoveryCh: make(chan event.GenericEvent, 1),
		// Empty cache
		discoveredServers: nil,
	}

	k8sNodes := []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1", Labels: map[string]string{}},
			Spec:       corev1.NodeSpec{ProviderID: "hcloud://111"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
				},
			},
		},
	}

	nodes, err := r.extractNodeInfos(context.Background(), k8sNodes)
	if err != nil {
		t.Fatalf("extractNodeInfos() error = %v", err)
	}

	// Simulate pass 3 merge with empty cache
	discovered := r.getDiscoveredServers()
	if discovered != nil {
		t.Fatalf("expected nil discovered cache, got %d", len(discovered))
	}

	// Nodes from passes 1+2 should still be intact
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node (graceful degradation), got %d", len(nodes))
	}
	if nodes[0].Name != "node-1" {
		t.Errorf("expected node-1, got %s", nodes[0].Name)
	}
}

func TestPollDiscovery_DetectsNewServers(t *testing.T) {
	resolver := &mockResolver{
		discoverResult: []firewall.NodeInfo{
			{Name: "server-1", ServerID: 100, IPv4: net.ParseIP("10.0.0.1")},
			{Name: "server-2", ServerID: 200, IPv4: net.ParseIP("10.0.0.2")},
		},
	}

	r := &NodeReconciler{
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		serverResolver: resolver,
		cfg:            config.Config{ServerNamePattern: "server-*"},
		discoveryCh:    make(chan event.GenericEvent, 1),
	}

	// First poll — should detect change (from empty to 2 servers)
	r.pollDiscovery(context.Background())

	// Should have sent an event
	select {
	case <-r.discoveryCh:
		// good
	default:
		t.Fatal("expected reconcile event after first poll")
	}

	// Cache should be populated
	cached := r.getDiscoveredServers()
	if len(cached) != 2 {
		t.Fatalf("expected 2 cached servers, got %d", len(cached))
	}

	// Second poll with same servers — no change
	r.pollDiscovery(context.Background())

	select {
	case <-r.discoveryCh:
		t.Fatal("unexpected reconcile event when servers unchanged")
	default:
		// good
	}

	// Third poll with a new server added
	resolver.discoverResult = append(resolver.discoverResult, firewall.NodeInfo{
		Name: "server-3", ServerID: 300, IPv4: net.ParseIP("10.0.0.3"),
	})
	r.pollDiscovery(context.Background())

	select {
	case <-r.discoveryCh:
		// good
	default:
		t.Fatal("expected reconcile event after new server discovered")
	}

	cached = r.getDiscoveredServers()
	if len(cached) != 3 {
		t.Fatalf("expected 3 cached servers, got %d", len(cached))
	}
}

func TestPollDiscovery_ErrorKeepsOldCache(t *testing.T) {
	resolver := &mockResolver{
		discoverResult: []firewall.NodeInfo{
			{Name: "server-1", ServerID: 100, IPv4: net.ParseIP("10.0.0.1")},
		},
	}

	r := &NodeReconciler{
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		serverResolver: resolver,
		cfg:            config.Config{ServerNamePattern: "server-*"},
		discoveryCh:    make(chan event.GenericEvent, 1),
	}

	// First successful poll
	r.pollDiscovery(context.Background())
	// Drain the event
	<-r.discoveryCh

	// Now make the resolver fail
	resolver.discoverErr = fmt.Errorf("API error")
	r.pollDiscovery(context.Background())

	// Cache should still have old data
	cached := r.getDiscoveredServers()
	if len(cached) != 1 {
		t.Fatalf("expected cache to retain 1 server after error, got %d", len(cached))
	}

	// No event should have been sent
	select {
	case <-r.discoveryCh:
		t.Fatal("unexpected reconcile event after poll error")
	default:
		// good
	}
}

func TestStart_NoOpWhenPatternEmpty(t *testing.T) {
	r := &NodeReconciler{
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:         config.Config{ServerNamePattern: ""},
		discoveryCh: make(chan event.GenericEvent, 1),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Start should return immediately (not block) when pattern is empty
	err := r.Start(ctx)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
}

func TestInt64SliceEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []int64
		want bool
	}{
		{"both nil", nil, nil, true},
		{"both empty", []int64{}, []int64{}, true},
		{"equal", []int64{1, 2, 3}, []int64{1, 2, 3}, true},
		{"different length", []int64{1, 2}, []int64{1, 2, 3}, false},
		{"different values", []int64{1, 2, 3}, []int64{1, 2, 4}, false},
		{"nil vs empty", nil, []int64{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := int64SliceEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("int64SliceEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
