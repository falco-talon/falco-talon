package cmd

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/falcosecurity/falco-talon/internal/handler"
	"github.com/falcosecurity/falco-talon/internal/otlp/metrics"
	"github.com/falcosecurity/falco-talon/internal/otlp/traces"

	"github.com/fsnotify/fsnotify"

	"github.com/falcosecurity/falco-talon/actionners"
	"github.com/falcosecurity/falco-talon/configuration"
	k8s "github.com/falcosecurity/falco-talon/internal/kubernetes/client"
	"github.com/falcosecurity/falco-talon/internal/nats"
	ruleengine "github.com/falcosecurity/falco-talon/internal/rules"
	"github.com/falcosecurity/falco-talon/notifiers"
	"github.com/falcosecurity/falco-talon/outputs"
	"github.com/falcosecurity/falco-talon/utils"

	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start Falco Talon server",
	Long:  "Start Falco Talon server.",
	Run: func(cmd *cobra.Command, _ []string) {
		configFile, _ := cmd.Flags().GetString("config")
		config := configuration.CreateConfiguration(configFile)
		utils.SetLogFormat(config.LogFormat)
		rulesFiles, _ := cmd.Flags().GetStringArray("rules")
		if len(rulesFiles) != 0 {
			config.RulesFiles = rulesFiles
		}
		rules := ruleengine.ParseRules(config.RulesFiles)
		if rules == nil {
			utils.PrintLog("fatal", utils.LogLine{Error: "invalid rules", Message: "rules"})
		}

		defaultActionners := actionners.ListDefaultActionners()
		defaultOutputs := outputs.ListDefaultOutputs()

		valid := true
		if rules != nil {
			for _, i := range *rules {
				for _, j := range i.GetActions() {
					actionner := defaultActionners.FindActionner(j.GetActionner())
					if actionner == nil {
						utils.PrintLog("error", utils.LogLine{Error: "unknown actionner", Rule: i.GetName(), Action: j.GetName(), Actionner: j.GetActionner(), Message: "rules"})
						valid = false
					} else {
						if err := actionner.CheckParameters(j); err != nil {
							utils.PrintLog("error", utils.LogLine{Error: err.Error(), Rule: i.GetName(), Action: j.GetName(), Actionner: j.GetActionner(), Message: "rules"})
							valid = false
						}
					}
					if actionner != nil {
						o := j.GetOutput()
						if o == nil && actionner.Information().RequireOutput {
							utils.PrintLog("error", utils.LogLine{Error: "an output is required", Rule: i.GetName(), Action: j.GetName(), Actionner: j.GetActionner(), Message: "rules"})
							valid = false
						}
						if o != nil {
							output := defaultOutputs.FindOutput(o.GetTarget())
							if output == nil {
								utils.PrintLog("error", utils.LogLine{Error: "unknown target", Rule: i.GetName(), Action: j.GetName(), OutputTarget: o.GetTarget(), Message: "rules"})
								valid = false
							} else if len(o.Parameters) == 0 {
								utils.PrintLog("error", utils.LogLine{Error: "missing parameters for the output", Rule: i.GetName(), Action: j.GetName(), OutputTarget: o.GetTarget(), Message: "rules"})
								valid = false
							} else {
								if err := output.CheckParameters(o); err != nil {
									utils.PrintLog("error", utils.LogLine{Error: err.Error(), Rule: i.GetName(), Action: j.GetName(), OutputTarget: o.GetTarget(), Message: "rules"})
									valid = false
								}
							}
						}
					}
				}
			}
		}
		if !valid {
			utils.PrintLog("fatal", utils.LogLine{Error: "invalid rules", Message: "rules"})
		}

		// init actionners
		if err := actionners.Init(); err != nil {
			utils.PrintLog("fatal", utils.LogLine{Error: err.Error(), Message: "actionners"})
		}

		// init outputs
		if err := outputs.Init(); err != nil {
			utils.PrintLog("fatal", utils.LogLine{Error: err.Error(), Message: "outputs"})
		}

		// init notifiers
		notifiers.Init()

		if rules != nil {
			utils.PrintLog("info", utils.LogLine{Result: fmt.Sprintf("%v rule(s) has/have been successfully loaded", len(*rules)), Message: "init"})
		}

		if config.WatchRules {
			utils.PrintLog("info", utils.LogLine{Result: "watch of rules enabled", Message: "init"})
		}

		srv := http.Server{
			Addr:         fmt.Sprintf("%s:%d", config.ListenAddress, config.ListenPort),
			ReadTimeout:  2 * time.Second,
			WriteTimeout: 2 * time.Second,
			Handler:      newHTTPHandler(),
		}

		if config.WatchRules {
			go func() {
				ignore := false
				watcher, err := fsnotify.NewWatcher()
				if err != nil {
					utils.PrintLog("error", utils.LogLine{Error: err.Error(), Message: "rules"})
					return
				}
				defer watcher.Close()
				for _, i := range config.RulesFiles {
					if err := watcher.Add(i); err != nil {
						utils.PrintLog("error", utils.LogLine{Error: err.Error(), Message: "rules"})
						return
					}
				}
				for {
					select {
					case event := <-watcher.Events:
						if event.Has(fsnotify.Write) && !ignore {
							ignore = true
							go func() {
								time.Sleep(1 * time.Second)
								ignore = false
							}()
							utils.PrintLog("info", utils.LogLine{Result: "changes detected", Message: "rules"})
							newRules := ruleengine.ParseRules(config.RulesFiles)
							if newRules == nil {
								utils.PrintLog("error", utils.LogLine{Error: "invalid rules", Message: "rules"})
								break
							}

							defaultActionners := actionners.ListDefaultActionners()
							defaultOutputs := outputs.ListDefaultOutputs()

							if newRules != nil {
								valid := true
								for _, i := range *newRules {
									for _, j := range i.GetActions() {
										actionner := defaultActionners.FindActionner(j.GetActionner())
										if actionner == nil {
											break
										}
										if err := actionner.CheckParameters(j); err != nil {
											utils.PrintLog("error", utils.LogLine{Error: err.Error(), Rule: i.GetName(), Message: "rules"})
											valid = false
										}
										o := j.GetOutput()
										if o == nil && actionner.Information().RequireOutput {
											utils.PrintLog("error", utils.LogLine{Error: "an output is required", Rule: i.GetName(), Action: j.GetName(), Actionner: j.GetActionner(), Message: "rules"})
											valid = false
										}
										if o != nil {
											output := defaultOutputs.FindOutput(o.GetTarget())
											if output == nil {
												utils.PrintLog("error", utils.LogLine{Error: "unknown target", Rule: i.GetName(), Action: j.GetName(), OutputTarget: o.GetTarget(), Message: "rules"})
												valid = false
											}
											if len(o.Parameters) == 0 {
												utils.PrintLog("error", utils.LogLine{Error: "missing parameters for the output", Rule: i.GetName(), Action: j.GetName(), OutputTarget: o.GetTarget(), Message: "rules"})
												valid = false
											}
											if err := output.CheckParameters(o); err != nil {
												utils.PrintLog("error", utils.LogLine{Error: err.Error(), Rule: i.GetName(), Action: j.GetName(), OutputTarget: o.GetTarget(), Message: "rules"})
												valid = false
											}
										}
									}

									if !valid {
										utils.PrintLog("error", utils.LogLine{Error: "invalid rules", Message: "rules"})
										break
									}
									utils.PrintLog("info", utils.LogLine{Result: fmt.Sprintf("%v rules have been successfully loaded", len(*rules)), Message: "rules"})
									rules = newRules
									if err := actionners.Init(); err != nil {
										utils.PrintLog("error", utils.LogLine{Error: err.Error(), Message: "actionners"})
										break
									}
								}
							}
						}
					case err := <-watcher.Errors:
						utils.PrintLog("error", utils.LogLine{Error: err.Error(), Message: "rules"})
					}
				}
			}()
		}
		// start the local NATS
		ns, err := nats.StartServer(config.Deduplication.TimeWindowSeconds)
		if err != nil {
			utils.PrintLog("fatal", utils.LogLine{Error: err.Error(), Message: "nats"})
		}
		defer ns.Shutdown()

		// starts a goroutine to get the holder of the lease
		if config.Deduplication.LeaderElection {
			go func() {
				err2 := k8s.Init()
				if err2 != nil {
					utils.PrintLog("fatal", utils.LogLine{Error: err2.Error(), Message: "lease"})
				}
				c, err2 := k8s.GetClient().GetLeaseHolder()
				if err2 != nil {
					utils.PrintLog("fatal", utils.LogLine{Error: err2.Error(), Message: "lease"})
				}
				for {
					s := <-c
					if s == *utils.GetLocalIP() {
						s = "127.0.0.1"
					}
					utils.PrintLog("info", utils.LogLine{Result: fmt.Sprintf("new leader detected '%v'", s), Message: "nats"})
					err2 = nats.GetPublisher().SetJetStreamContext("nats://" + s + ":4222")
					if err2 != nil {
						utils.PrintLog("error", utils.LogLine{Error: err2.Error(), Message: "nats"})
					}
				}
			}()
		}

		// start the consumer for the actionners
		c, err := nats.GetConsumer().ConsumeMsg()

		if err != nil {
			utils.PrintLog("fatal", utils.LogLine{Error: err.Error(), Message: "nats"})
		}
		go actionners.StartConsumer(c)

		utils.PrintLog("info", utils.LogLine{Result: fmt.Sprintf("Falco Talon is up and listening on %s:%d", config.ListenAddress, config.ListenPort), Message: "http"})

		ctx := context.Background()
		otelShutdown, err := traces.SetupOTelSDK(ctx)
		if err != nil {
			utils.PrintLog("warn", utils.LogLine{Error: err.Error(), Message: "otel-traces"})
		}
		defer func() {
			if err := otelShutdown(ctx); err != nil {
				utils.PrintLog("warn", utils.LogLine{Error: err.Error(), Message: "otel-traces"})
			}
		}()

		metrics.Init()

		if err := srv.ListenAndServe(); err != nil {
			utils.PrintLog("fatal", utils.LogLine{Error: err.Error(), Message: "http"})
		}
	},
}

func newHTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())

	handleFunc := func(pattern string, handlerFunc func(http.ResponseWriter, *http.Request)) {
		otelHandler := otelhttp.WithRouteTag(pattern, http.HandlerFunc(handlerFunc))
		mux.Handle(pattern, otelHandler)
	}

	handleFunc("/", handler.MainHandler)
	handleFunc("/healthz", handler.HealthHandler)

	otelHandler := otelhttp.NewHandler(
		mux,
		"/",
		otelhttp.WithFilter(func(req *http.Request) bool {
			return req.URL.Path == "/"
		}))
	return otelHandler
}
