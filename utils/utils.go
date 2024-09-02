package utils

import (
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	validator "github.com/go-playground/validator/v10"
	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog"
)

const (
	FalcoTalonStr string = "falco-talon"

	BoolStr           string = "bool"
	FloatStr          string = "float"
	Float64Str        string = "float64"
	StringStr         string = "string"
	IntStr            string = "int"
	Int64Str          string = "int64"
	SliceInterfaceStr string = "[]interface {}"
	MapStringStr      string = "map[string]string"
	MapIntStr         string = "map[string]int"
	MapInterfaceStr   string = "map[string]interface {}"

	errorStr   string = "error"
	warningStr string = "warning"
	fatalStr   string = "fatal"

	textStr  string = "text"
	colorStr string = "color"

	SuccessStr string = "success"
	FailureStr string = "failure"

	ansiChars string = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
)

type LogLine struct {
	Time              string            `json:"time,omitempty"`
	Objects           map[string]string `json:"objects,omitempty"`
	TraceID           string            `json:"trace_id,omitempty"`
	Rule              string            `json:"rule,omitempty"`
	Event             string            `json:"event,omitempty"`
	Message           string            `json:"message,omitempty"`
	Priority          string            `json:"priority,omitempty"`
	Source            string            `json:"source,omitempty"`
	Result            string            `json:"result,omitempty"`
	Notifier          string            `json:"notifier,omitempty"`
	Context           string            `json:"context,omitempty"`
	Output            string            `json:"output,omitempty"`
	ActionnerCategory string            `json:"actionner_category,omitempty"`
	OutputName        string            `json:"output_name,omitempty"`
	OutputCategory    string            `json:"output_category,omitempty"`
	OutputTarget      string            `json:"output_target,omitempty"`
	Actionner         string            `json:"actionner,omitempty"`
	Action            string            `json:"action,omitempty"`
	Error             string            `json:"error,omitempty"`
	Status            string            `json:"status,omitempty"`
	Stage             string            `json:"stage,omitempty"`
}

var validate *validator.Validate
var localIP *string
var logFormat *string

func init() {
	logFormat = new(string)
	*logFormat = colorStr
	validate = validator.New(validator.WithRequiredStructEnabled())
}

func SetLogFormat(format string) {
	if logFormat != nil {
		*logFormat = strings.ToLower(format)
	}
}

func PrintLog(level string, line LogLine) {
	var output zerolog.ConsoleWriter

	var log zerolog.Logger
	if *logFormat == textStr || *logFormat == colorStr {
		output = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
		if *logFormat != colorStr {
			output.NoColor = true
		}
		output.FormatFieldValue = func(i interface{}) string {
			return fmt.Sprintf("%s", i)
		}
		log = zerolog.New(output).With().Timestamp().Logger()
	} else {
		log = zerolog.New(os.Stdout).With().Timestamp().Logger()
	}

	var l *zerolog.Event
	switch strings.ToLower(level) {
	case warningStr:
		l = log.Warn()
	case errorStr:
		l = log.Error()
	case fatalStr:
		l = log.Fatal()
	default:
		l = log.Info()
	}
	if line.Rule != "" {
		l.Str("rule", line.Rule)
	}
	if line.Event != "" {
		l.Str("event", line.Event)
	}
	if line.Priority != "" {
		l.Str("priority", line.Priority)
	}
	if line.Source != "" {
		l.Str("source", line.Source)
	}
	if line.Notifier != "" {
		l.Str("notifier", line.Notifier)
	}
	if line.Context != "" {
		l.Str("context", line.Context)
	}
	if line.Output != "" {
		l.Str("output", line.Output)
	}
	if line.Stage != "" {
		l.Str("stage", line.Stage)
	}
	if line.Actionner != "" {
		l.Str("actionner", line.Actionner)
	}
	if line.ActionnerCategory != "" {
		l.Str("actionner_category", line.ActionnerCategory)
	}
	if line.OutputCategory != "" {
		l.Str("output_category", line.OutputCategory)
	}
	if line.OutputTarget != "" {
		l.Str("output_target", line.OutputTarget)
	}
	if line.Action != "" {
		l.Str("action", line.Action)
	}
	if line.Status != "" {
		l.Str("status", line.Status)
	}
	if line.Result != "" {
		l.Str("result", line.Result)
	}
	if line.TraceID != "" {
		l.Str("trace_id", line.TraceID)
	}
	if len(line.Objects) > 0 {
		for i, j := range line.Objects {
			l.Str(strings.ToLower(i), j)
		}
	}
	if line.Error != "" {
		l.Err(errors.New(line.Error))
	}
	if line.Message != "" {
		l.Msg(line.Message)
	}
}

func SetFields(structure interface{}, fields map[string]interface{}) interface{} {
	valueOf := reflect.ValueOf(structure)
	if valueOf.Kind() == reflect.Ptr {
		valueOf = valueOf.Elem()
	}

	for i := 0; i < valueOf.NumField(); i++ {
		fieldType := valueOf.Type().Field(i)
		field := fieldType.Tag.Get("field")
		deflt := fieldType.Tag.Get("default")
		if fields[field] != nil {
			switch valueOf.Type().Field(i).Type.String() {
			case StringStr:
				valueOf.Field(i).SetString(fmt.Sprint(fields[field]))
			case IntStr, Int64Str:
				d, err := strconv.Atoi(fmt.Sprintf("%v", fields[field]))
				if err == nil {
					valueOf.Field(i).SetInt(int64(d))
				} else if deflt != "" {
					d, _ := strconv.Atoi(deflt)
					valueOf.Field(i).SetInt(int64(d))
				}
			case FloatStr, Float64Str:
				d, err := strconv.ParseFloat(fmt.Sprintf("%v", fields[field]), 64)
				if err == nil {
					valueOf.Field(i).SetFloat(d)
				} else if deflt != "" {
					d, _ := strconv.ParseFloat(deflt, 64)
					valueOf.Field(i).SetFloat(d)
				}
			case BoolStr:
				d, err := strconv.ParseBool(fmt.Sprintf("%v", fields[field]))
				if err == nil {
					valueOf.Field(i).SetBool(d)
				} else if deflt != "" {
					d, _ := strconv.ParseBool(deflt)
					valueOf.Field(i).SetBool(d)
				}
			case MapStringStr:
				valueOf.Field(i).SetMapIndex(reflect.ValueOf(fields[field]), reflect.ValueOf(fields[field]).Elem())
			}
		} else if deflt != "" {
			switch valueOf.Type().Field(i).Type.String() {
			case StringStr:
				valueOf.Field(i).SetString(deflt)
			case IntStr, Int64Str:
				d, _ := strconv.Atoi(deflt)
				valueOf.Field(i).SetInt(int64(d))
			case FloatStr, Float64Str:
				d, _ := strconv.ParseFloat(deflt, 64)
				valueOf.Field(i).SetFloat(d)
			case BoolStr:
				d, _ := strconv.ParseBool(deflt)
				valueOf.Field(i).SetBool(d)
			}
		}
	}

	return structure
}

func ValidateStruct(s interface{}) error {
	err := validate.Struct(s)
	if err != nil {
		return err
	}
	return nil
}

func AddCustomValidation(tag string, fn validator.Func) error {
	err := validate.RegisterValidation(tag, fn)
	if err != nil {
		return err
	}
	return nil
}

func AddCustomStructValidation(s interface{}, fn validator.StructLevelFunc) {
	validate.RegisterStructValidation(fn, s)
}

func DecodeParams(params map[string]interface{}, result interface{}) error {
	// Decode parameters into the struct
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName: "mapstructure",
		Result:  result,
	})
	if err != nil {
		return fmt.Errorf("error creating decoder: %w", err)
	}
	if err := decoder.Decode(params); err != nil {
		return fmt.Errorf("error decoding parameters: %w", err)
	}
	return nil
}

func RemoveSpecialCharacters(input string) string {
	return strings.ReplaceAll(input, "\r\n", "\n")
}

func RemoveAnsiCharacters(str string) string {
	var reg = regexp.MustCompile(ansiChars)
	return reg.ReplaceAllString(str, "")
}

func Deduplicate[T comparable](s []T) []T {
	inResult := make(map[T]bool)
	var result []T
	for _, str := range s {
		if _, ok := inResult[str]; !ok {
			inResult[str] = true
			result = append(result, str)
		}
	}
	return result
}

func GetLocalIP() *string {
	if localIP != nil {
		return localIP
	}
	localIP = new(string)
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				*localIP = ipnet.IP.String()
			}
		}
	}
	return localIP
}
