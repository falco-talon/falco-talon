package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-playground/validator/v10"

	"github.com/falco-talon/falco-talon/internal/events"
	httpClient "github.com/falco-talon/falco-talon/internal/http"
	"github.com/falco-talon/falco-talon/internal/rules"
	"github.com/falco-talon/falco-talon/outputs/model"
	"github.com/falco-talon/falco-talon/utils"
)

type AuthConfig struct {
	Username string `mapstructure:"username" validate:"required_with=Password,omitempty"`
	Password string `mapstructure:"password" validate:"required_with=Username,omitempty"`
	Token    string `mapstructure:"token" validate:"omitempty"`
}

type HTTPConfig struct {
	Headers map[string]string `mapstructure:"headers" validate:"omitempty"`
	Method  string            `mapstructure:"method" validate:"omitempty,oneof=GET POST PUT DELETE PATCH"`
	Timeout int               `mapstructure:"timeout" validate:"omitempty"`
}

type Config struct {
	Auth            AuthConfig  `mapstructure:"auth_config" validate:"omitempty"`
	HTTPConfig      *HTTPConfig `mapstructure:"http_config" validate:"omitempty"`
	Endpoint        string      `mapstructure:"endpoint" validate:"required,url"`
	Port            int         `mapstructure:"port" validate:"required"`
	InsecureSkipTLS bool        `mapstructure:"insecure_skip_tls" validate:"omitempty"`
}

func Action(action *rules.Action, event *events.Event) (utils.LogLine, *model.Data, error) {
	var actionConfig Config
	err := utils.DecodeParams(action.GetParameters(), &actionConfig)
	if err != nil {
		return utils.LogLine{
				Objects: nil,
				Error:   err.Error(),
				Status:  "failure",
			},
			nil,
			err
	}

	client := httpClient.GetClient()

	httpClient.OverrideClientSettings(client, actionConfig.InsecureSkipTLS, actionConfig.HTTPConfig.Timeout)

	err = callHTTP(client, actionConfig, event)
	if err != nil {
		return utils.LogLine{
				Error:  err.Error(),
				Status: "failure",
			},
			nil,
			err
	}

	return utils.LogLine{
		Message: "successfully called webhook",
		Status:  "success",
	}, nil, nil
}

func CheckParameters(action *rules.Action) error {
	parameters := action.GetParameters()

	var config Config

	err := utils.DecodeParams(parameters, &config)
	if err != nil {
		return err
	}

	utils.AddCustomStructValidation(AuthConfig{}, authConfigStructLevelValidation)

	err = utils.ValidateStruct(config)
	if err != nil {
		return err
	}

	return nil
}

func callHTTP(client *http.Client, config Config, event *events.Event) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}

	method := http.MethodPost
	if config.HTTPConfig.Method != "" {
		method = config.HTTPConfig.Method
	}

	url := fmt.Sprintf("%s:%d", config.Endpoint, config.Port)
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	for key, value := range config.HTTPConfig.Headers {
		req.Header.Set(key, value)
	}

	if config.Auth.Token != "" {
		req.Header.Set("Authorization", "Bearer "+config.Auth.Token)
	} else if config.Auth.Username != "" && config.Auth.Password != "" {
		req.SetBasicAuth(config.Auth.Username, config.Auth.Password)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("received non-2xx response status: %d", resp.StatusCode)
	}

	return nil
}

func authConfigStructLevelValidation(sl validator.StructLevel) {
	authConfig := sl.Current().Interface().(AuthConfig)

	if authConfig.Token != "" {
		if authConfig.Username != "" || authConfig.Password != "" {
			sl.ReportError(authConfig.Token, "Token", "Token", "auth_config requires either token or username and password.", "")
		}
	} else {
		if authConfig.Username == "" || authConfig.Password == "" {
			sl.ReportError(authConfig.Username, "Username", "Username", "auth_config accepts only token or username and password", "")
			sl.ReportError(authConfig.Password, "Password", "Password", "auth_config accepts only token or username and password", "")
		}
	}
}
