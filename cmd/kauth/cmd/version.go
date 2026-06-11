package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	GitCommit = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("  kauth %s  %s\n", accent.Render("v"+Version), muted.Render("("+GitCommit+")"))
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
