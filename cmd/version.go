package cmd

import (
	"fmt"

	"github.com/falcosecurity/falco-talon/configuration"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version of Falco Talon.",
	Long:  "Print version of Falco Talon",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println(configuration.GetInfo().String())
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
