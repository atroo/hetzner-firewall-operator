package controller

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/atroo/hetzner-firewall-operator/internal/firewall"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// mockResolver implements firewall.ServerResolver for testing.
type mockResolver struct {
	result map[string]int64
	err    error
}

func (m *mockResolver) ResolveServerIDs(_ context.Context, names []string) (map[string]int64, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
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
		t.Error("worker-1 should have IPv6Net")
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
