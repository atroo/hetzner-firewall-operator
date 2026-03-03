package main

import (
	"flag"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/atroo/hetzner-firewall-operator/internal/config"
	"github.com/atroo/hetzner-firewall-operator/internal/controller"
	"github.com/atroo/hetzner-firewall-operator/internal/firewall"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	var (
		firewallName      string
		reconcileInterval time.Duration
		allowSSH          string
		nodePortPublic    bool
		metricsAddr       string
		labelSelector     string
	)

	flag.StringVar(&firewallName, "firewall-name", envOrDefault("FIREWALL_NAME", "k8s-cluster"), "Name of the Hetzner firewall to manage")
	flag.DurationVar(&reconcileInterval, "reconcile-interval", 5*time.Minute, "Interval between full reconciliations")
	flag.StringVar(&allowSSH, "allow-ssh-from", envOrDefault("ALLOW_SSH_FROM", ""), "Comma-separated CIDRs for SSH access (empty=no SSH rule)")
	flag.BoolVar(&nodePortPublic, "nodeport-public", false, "Expose NodePort range (30000-32767) to the internet")
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "Address for metrics endpoint")
	flag.StringVar(&labelSelector, "label-selector", "", "Label selector to filter nodes")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Get Hetzner Cloud token
	hcloudToken := os.Getenv("HCLOUD_TOKEN")
	if hcloudToken == "" {
		logger.Error("HCLOUD_TOKEN environment variable is required")
		os.Exit(1)
	}

	// Parse SSH CIDRs
	var sshCIDRs []string
	if allowSSH != "" {
		sshCIDRs = strings.Split(allowSSH, ",")
		for i := range sshCIDRs {
			sshCIDRs[i] = strings.TrimSpace(sshCIDRs[i])
		}
	}

	cfg := config.Config{
		HCloudToken:       hcloudToken,
		FirewallName:      firewallName,
		AllowSSHFrom:      sshCIDRs,
		NodePortPublic:    nodePortPublic,
		ReconcileInterval: reconcileInterval,
		LabelSelector:     labelSelector,
	}

	logger.Info("starting hetzner-firewall-operator",
		"firewallName", cfg.FirewallName,
		"reconcileInterval", cfg.ReconcileInterval,
		"nodePortPublic", cfg.NodePortPublic,
		"sshCIDRs", len(cfg.AllowSSHFrom),
	)

	// Create Hetzner Cloud client
	hcloudClient := hcloud.NewClient(hcloud.WithToken(hcloudToken))

	// Create firewall client
	fwClient := firewall.NewClient(hcloudClient, cfg, logger)

	// Setup controller-runtime manager
	opts := zap.Options{Development: false}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		// Leader election for HA deployments
		LeaderElection:   true,
		LeaderElectionID: "hetzner-firewall-operator",
	})
	if err != nil {
		logger.Error("unable to create manager", "error", err)
		os.Exit(1)
	}

	// Create and register the node reconciler
	reconciler := controller.NewNodeReconciler(
		mgr.GetClient(),
		fwClient,
		fwClient, // also serves as ServerResolver for RKE2 fallback
		cfg,
		logger,
	)

	if err := reconciler.SetupWithManager(mgr); err != nil {
		logger.Error("unable to create controller", "error", err)
		os.Exit(1)
	}

	logger.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error("manager exited with error", "error", err)
		os.Exit(1)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
