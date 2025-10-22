package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kauth",
	Short: "Kubernetes OIDC authentication client",
	Long: `kauth provides simple OIDC authentication for Kubernetes clusters.

Just run:
  kauth login --url https://kauth.example.com

Your browser will open, you'll authenticate, and kubectl will be configured automatically.`,
}

func Execute() error {
	return rootCmd.Execute()
}
