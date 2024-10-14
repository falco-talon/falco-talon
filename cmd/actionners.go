package cmd

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/falcosecurity/falco-talon/actionners"
)

var actionnersCmd = &cobra.Command{
	Use:   "actionners",
	Short: "Manage the actionners",
	Long:  "Manage the actionners",
	Run:   nil,
}

var actionnersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the available Actionners",
	Long:  "List the available Actionners.",
	Run: func(_ *cobra.Command, _ []string) {
		defaultActionners := actionners.ListDefaultActionners()
		type actionner struct { // nolint:govet
			Parameters           map[string]any `yaml:"parameters"`
			Name                 string         `yaml:"name"`
			Category             string         `yaml:"category"`
			Description          string         `yaml:"description"`
			Source               string         `yaml:"source"`
			Permissions          string         `yaml:"permissions,omitempty"`
			Example              string         `yaml:"example,omitempty"`
			RequiredOutputFields []string       `yaml:"required_output_fields"`
			Continue             bool           `yaml:"continue"`
			UseContext           bool           `yaml:"use_context"`
			AllowOutput          bool           `yaml:"allow_output"`
			RequireOutput        bool           `yaml:"require_output"`
		}

		for _, i := range *defaultActionners {
			parameters := make(map[string]any)
			a := actionner{
				Name:                 i.Information().Name,
				Category:             i.Information().Category,
				Description:          i.Information().Description,
				Source:               i.Information().Source,
				RequiredOutputFields: i.Information().RequiredOutputFields,
				Continue:             i.Information().Continue,
				UseContext:           i.Information().UseContext,
				AllowOutput:          i.Information().AllowOutput,
				RequireOutput:        i.Information().RequireOutput,
				Permissions:          i.Information().Permissions,
				Example:              i.Information().Example,
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
