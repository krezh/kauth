package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kauth",
	Short: "Kubernetes OIDC authentication client",
	Long: `kauth provides simple OIDC authentication for Kubernetes clusters.

Just run:
  kauth login

Clusters are discovered automatically via DNS. Your browser will open,
you'll authenticate, and kubectl will be configured automatically.`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

func Execute() error {
	return rootCmd.Execute()
}
