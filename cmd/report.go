package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate markdown report from findings",
	Example: `  bbscout report --target example.com --output report.md`,
	RunE: func(cmd *cobra.Command, args []string) error {
		target, _ := cmd.Flags().GetString("target")
		output, _ := cmd.Flags().GetString("output")
		fmt.Printf("[report] coming soon — target: %s, output: %s\n", target, output)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(reportCmd)
	reportCmd.Flags().StringP("target", "t", "", "target domain (required)")
	reportCmd.Flags().StringP("output", "o", "report.md", "output file path")
	reportCmd.MarkFlagRequired("target")
}