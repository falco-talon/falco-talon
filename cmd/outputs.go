package cmd

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/falcosecurity/falco-talon/outputs"
)

var outputsCmd = &cobra.Command{
	Use:   "outputs",
	Short: "Manage the Outputs",
	Long:  "Manage the Outputs.",
	Run:   nil,
}

var outputsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the available Outputs",
	Long:  "List the available Outputs.",
	Run: func(_ *cobra.Command, _ []string) {
		defaultOuputs := outputs.ListDefaultOutputs()
		type output struct { //nolint:govet
			Name        string         `yaml:"name"`
			Category    string         `yaml:"category"`
			Description string         `yaml:"description"`
			Parameters  map[string]any `yaml:"parameters"`
			Permissions string         `yaml:"permissions,omitempty"`
			Example     string         `yaml:"example,omitempty"`
		}

		for _, i := range *defaultOuputs {
			parameters := make(map[string]any)
			a := output{
				Name:        i.Information().Name,
				Category:    i.Information().Category,
				Description: i.Information().Description,
				Permissions: i.Information().Permissions,
				Example:     i.Information().Example,
			}

			if p := i.Parameters(); p != nil {
				valueOf := reflect.ValueOf(i.Parameters())
				if valueOf.Kind() == reflect.Ptr {
					valueOf = valueOf.Elem()
				}

				for i := 0; i < valueOf.NumField(); i++ {
					field := valueOf.Type().Field(i)
					var r string
					if strings.Contains(field.Tag.Get("validate"), "required") {
						r = requiredStr
					}
					parameters[field.Tag.Get("mapstructure")+r] = valueOf.Field(i).Interface()
				}

				a.Parameters = parameters
			}
			yamla, _ := yaml.Marshal(a)
			fmt.Printf("--- %v ---\n\n", i.Information().FullName)
			fmt.Println(string(yamla))
		}
	},
}
