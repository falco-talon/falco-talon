package configuration

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"

	"github.com/falcosecurity/falco-talon/utils"
)

const (
	defaultListenAddress                string = "0.0.0.0"
	defaultListPort                     int    = 2803
	defaultRulesFile                    string = "/etc/falco-talon/rules.yaml"
	defaultWatchRules                   bool   = true
	defaultPrintAllEvents               bool   = false
	defaultDeduplicationLeaderElection  bool   = true
	defaultDeduplicationTimeWindow      int    = 5
	defaultOtelCollectorTracesEnabled   bool   = false
	defaultOtelCollectorMetricsEnabled  bool   = false
	defaultOtelCollectorEndpoint        string = "localhost"
	defaultOtelCollectorUseInsecureGrpc bool   = false
	defaultOtelCollectorPort            int    = 4317
	defaultOtelCollectorGRPCTimeout            = 10
)

type Otel struct {
	CollectorEndpoint        string `mapstructure:"collector_endpoint"`
	CollectorPort            string `mapstructure:"collector_port"`
	Timeout                  int    `mapstructure:"timeout"`
	CollectorUseInsecureGrpc bool   `mapstructure:"collector_use_insecure_grpc"`
	TracesEnabled            bool   `mapstructure:"traces_enabled"`
	MetricsEnabled           bool   `mapstructure:"metrics_enabled"`
}

type Configuration struct {
	Notifiers        map[string]map[string]interface{} `mapstructure:"notifiers"`
	AwsConfig        AwsConfig                         `mapstructure:"aws"`
	GcpConfig        GcpConfig                         `mapstructure:"gcp"`
	LogFormat        string                            `mapstructure:"log_format"`
	KubeConfig       string                            `mapstructure:"kubeconfig"`
	ListenAddress    string                            `mapstructure:"listen_address"`
	MinioConfig      MinioConfig                       `mapstructure:"minio"`
	RulesFiles       []string                          `mapstructure:"rules_files"`
	DefaultNotifiers []string                          `mapstructure:"default_notifiers"`
	Otel             Otel                              `mapstructure:"otel"`
	Deduplication    deduplication                     `mapstructure:"deduplication"`
	ListenPort       int                               `mapstructure:"listen_port"`
	WatchRules       bool                              `mapstructure:"watch_rules"`
	PrintAllEvents   bool                              `mapstructure:"print_all_events"`
}

type deduplication struct {
	LeaderElection    bool `mapstructure:"leader_election"`
	TimeWindowSeconds int  `mapstructure:"time_window_seconds"`
}

type AwsConfig struct {
	Region     string `mapstructure:"region"`
	AccessKey  string `mapstructure:"access_key"`
	SecretKey  string `mapstructure:"secret_key"`
	RoleArn    string `mapstructure:"role_arn"`
	ExternalID string `mapstructure:"external_id"`
}

type GcpConfig struct {
	Region          string `mapstructure:"region"`
	CredentialsPath string `mapstructure:"credentials_path"`
}

type MinioConfig struct {
	Endpoint  string `mapstructure:"endpoint"`
	AccessKey string `mapstructure:"access_key"`
	SecretKey string `mapstructure:"secret_key"`
	UseSSL    bool   `mapstructure:"use_ssl"`
}

var config *Configuration

func init() {
	config = new(Configuration)
}

func CreateConfiguration(configFile string) *Configuration {
	v := viper.New()
	v.SetDefault("listen_address", defaultListenAddress)
	v.SetDefault("listen_port", defaultListPort)
	v.SetDefault("rules_files", []string{defaultRulesFile})
	v.SetDefault("kubeconfig", "")
	v.SetDefault("log_format", "color")
	v.SetDefault("default_notifiers", []string{})
	v.SetDefault("watch_rules", defaultWatchRules)
	v.SetDefault("print_all_events", defaultPrintAllEvents)
	v.SetDefault("deduplication.leader_election", defaultDeduplicationLeaderElection)
	v.SetDefault("deduplication.time_window_seconds", defaultDeduplicationTimeWindow)
	v.SetDefault("otel.traces_enabled", defaultOtelCollectorTracesEnabled)
	v.SetDefault("otel.metrics_enabled", defaultOtelCollectorMetricsEnabled)
	v.SetDefault("otel.collector_endpoint", defaultOtelCollectorEndpoint)
	v.SetDefault("otel.collector_port", defaultOtelCollectorPort)
	v.Set("otel.timeout", defaultOtelCollectorGRPCTimeout)
	v.SetDefault("otel.collector_use_insecure_grpc", defaultOtelCollectorUseInsecureGrpc)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if configFile != "" {
		v.SetConfigFile(configFile)
		err := v.ReadInConfig()
		if err != nil {
			utils.PrintLog("fatal", utils.LogLine{Error: fmt.Sprintf("error when reading config file: '%v'", err.Error()), Message: "config"})
		}
	}

	if err := v.Unmarshal(config); err != nil {
		utils.PrintLog("fatal", utils.LogLine{Error: fmt.Sprintf("error unmarshalling config file: '%v'", err.Error()), Message: "config"})
	}

	return config
}

func GetConfiguration() *Configuration {
	return config
}

func (c *Configuration) ListDefaultNotifiers() []string {
	return c.DefaultNotifiers
}
