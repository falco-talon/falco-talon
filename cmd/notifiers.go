package cmd

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/falcosecurity/falco-talon/notifiers"
)

var notifiersCmd = &cobra.Command{
	Use:   "notifiers",
	Short: "Manage the Notifiers",
	Long:  "Manage the Notifiers.",
	Run:   nil,
}

var notifiersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the available Notifiers",
	Long:  "List the available Notifiers.",
	Run: func(_ *cobra.Command, _ []string) {
		defaultOuputs := notifiers.ListDefaultNotifiers()
		type output struct { //nolint:govet
			Name        string         `yaml:"name"`
			Description string         `yaml:"description"`
			Parameters  map[string]any `yaml:"parameters,omitempty"`
			Permissions string         `yaml:"permissions,omitempty"`
			Example     string         `yaml:"example,omitempty"`
		}

		for _, i := range *defaultOuputs {
			parameters := make(map[string]any)
			a := output{
				Name:        i.Information().Name,
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
					parameters[field.Tag.Get("field")+r] = valueOf.Field(i).Interface()
				}

				a.Parameters = parameters
			}
			yamla, _ := yaml.Marshal(a)
			fmt.Printf("--- %v ---\n\n", i.Information().FullName)
			fmt.Println(string(yamla))
		}
	},
}
