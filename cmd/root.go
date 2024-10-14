package cmd

import (
	"github.com/spf13/cobra"

	"github.com/falcosecurity/falco-talon/utils"
)

const (
	requiredStr = " (required)"
)

var RootCmd = &cobra.Command{
	Use:   "falco-talon",
	Short: "Falco Talon is a Response Engine for managing threats in Kubernetes",
	Long: `Falco Talon is a Response Engine for managing threats in Kubernetes 
It enhances the solutions proposed by Falco community with a dedicated, 
no-code solution. With easy rules, you can perform actions over compromised pods.`,
}

func Execute() {
	err := RootCmd.Execute()
	if err != nil {
		utils.PrintLog("fatal", utils.LogLine{Error: err.Error()})
	}
}

func init() {
	RootCmd.AddCommand(serverCmd)
	RootCmd.AddCommand(rulesCmd)
	RootCmd.AddCommand(actionnersCmd)
	RootCmd.AddCommand(outputsCmd)
	RootCmd.AddCommand(notifiersCmd)
	rulesCmd.AddCommand(rulesChecksCmd)
	rulesCmd.AddCommand(rulesPrintCmd)
	actionnersCmd.AddCommand(actionnersListCmd)
	outputsCmd.AddCommand(outputsListCmd)
	notifiersCmd.AddCommand(notifiersListCmd)
	RootCmd.PersistentFlags().StringP("config", "c", "/etc/falco-talon/config.yaml", "Falco Talon Config File")
	RootCmd.PersistentFlags().StringArrayP("rules", "r", []string{"/etc/falco-talon/rules.yaml"}, "Falco Talon Rules File")
}
