// Package sdhook provides a logrus compatible logging hook for Google
// Stackdriver logging.
package sdhook

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/facebookgo/stack"
	"github.com/fluent/fluent-logger-golang/fluent"
	"github.com/sirupsen/logrus"

	clouderrorreporting "google.golang.org/api/clouderrorreporting/v1beta1"
	logging "google.golang.org/api/logging/v2"
	googleLogging "cloud.google.com/go/logging"
	"cloud.google.com/go/errorreporting"



	"google.golang.org/genproto/googleapis/api/monitoredres"
)

const (
	// DefaultName is the default name passed to LogName when using service
	// account credentials.
	DefaultName = "default"
)
const (
 TraceStr = "trace"
 LatencyStr = "latency"
 ResponseSizeStr = "responsesize"
 ResponseCodeStr = "responsecode"
 ClientIPStr = "clientip"
 LocalIPStr = "localip"
 LabelPrefixStr = "label:"
)
type Trace string
type Latency time.Duration
type ResponseSize int64
type ResponseCode int
type ClientIP string
type LocalIP string
type Label string

type DefaultAgentLogger struct {
	agentClientLogger *googleLogging.Logger
	monitoredResource *monitoredres.MonitoredResource
	errorreportingClient *errorreporting.Client
	labels  map[string] string
}
// StackdriverHook provides a logrus hook to Google Stackdriver logging.
type StackdriverHook struct {
	// levels are the levels that logrus will hook to.
	levels []logrus.Level

	// projectID is the projectID
	projectID string

	// service is the logging service.
	service *logging.EntriesService

	// service is the error reporting service.
	errorService *clouderrorreporting.Service


	resource *logging.MonitoredResource

	// logName is the name of the log.
	logName string

	// labels are the labels to send with each log entry.
	labels map[string]string

	// partialSuccess allows partial writes of log entries if there is a badly
	// formatted log.
	partialSuccess bool


	defaultAgentLogger *DefaultAgentLogger
	// fluentAgentClient defines the fluentd logger object that can send data to
	// to the Google logging agent.
	fluentAgentClient *fluent.Fluent

	// errorReportingServiceName defines the value of the field <service>,
	// required for a valid error reporting payload. If this value is set,
	// messages where level/severity is higher than or equal to "error" will
	// be sent to Stackdriver error reporting.
	// See more at:
	// https://cloud.google.com/error-reporting/docs/formatting-error-messages
	errorReportingServiceName string

	// errorReportingLogName is the name of the log for error reporting.
	// It must contain the string "error"
	// If not given, the string "<logName>_error" is used.
	errorReportingLogName string


	closeHandlers []func() error
}

// New creates a StackdriverHook using the provided options that is suitible
// for using with logrus for logging to Google Stackdriver.
func New(opts ...Option) (*StackdriverHook, error) {
	var err error

	sh := &StackdriverHook{
		levels: logrus.AllLevels,
	}

	// apply opts
	for _, o := range opts {
		err = o(sh)
		if err != nil {
			return nil, err
		}
	}

	// check service, resource, logName set
	if sh.service == nil && sh.fluentAgentClient == nil && sh.defaultAgentLogger == nil {
		return nil, errors.New("no stackdriver service was provided")
	}
	if sh.resource == nil && sh.fluentAgentClient == nil &&sh.defaultAgentLogger.monitoredResource ==nil{
		return nil, errors.New("the monitored resource was not provided")
	}
	if sh.projectID == "" && sh.fluentAgentClient == nil {
		return nil, errors.New("the project id was not provided")
	}

	// set default project name
	if sh.logName == "" {
		err = LogName(DefaultName)(sh)
		if err != nil {
			return nil, err
		}
	}

	// If error reporting log name not set, set it to log name
	// plus string suffix
	if sh.errorReportingLogName == "" {
		sh.errorReportingLogName = sh.logName + "_errors"
	}

	return sh, nil
}

func isError(entry *logrus.Entry) bool {
	if entry != nil {
		switch entry.Level {
		case logrus.ErrorLevel:
			return true
		case logrus.FatalLevel:
			return true
		case logrus.PanicLevel:
			return true
		}
	}
	return false
}

// Levels returns the logrus levels that this hook is applied to. This can be
// set using the Levels Option.
func (sh *StackdriverHook) Levels() []logrus.Level {
	return sh.levels
}

// Fire writes the message to the Stackdriver entry service.
func (sh *StackdriverHook) Fire(entry *logrus.Entry) error {
	func(entry *logrus.Entry) {
		var loggingHttpReq *logging.HttpRequest
		var latency *Latency
		var trace *Trace
		var responseCode *ResponseCode
		var responseSize *ResponseSize
		var clientIP *ClientIP
		var localIP *LocalIP
		var httpReq *http.Request
		extendedMessage := ""
		// convert entry data to labels
		labels := make(map[string]string, len(entry.Data))
		for k, v := range entry.Data {
			switch x := v.(type) {
			case string:
				switch (k){
					case TraceStr:
						tmp := Trace(x)
						trace = &tmp

					case ClientIPStr:
						tmp := ClientIP(x)
						clientIP = &tmp

					case LocalIPStr:
						tmp := LocalIP(x)
						localIP = &tmp
					default:
						if(strings.HasPrefix(k,LabelPrefixStr)){
							trimedKey := strings.TrimPrefix(k, LabelPrefixStr)
							labels[trimedKey]=x
						}else{
							extendedMessage = fmt.Sprintf("%v %v=%v",extendedMessage,k,v)
						}

				}
				//extendedMessage = fmt.Sprintf("%v %v=%v",extendedMessage,k,v)
			case time.Duration:
				if(k == LatencyStr){
					tmp := Latency(x)
					latency = &tmp
				} else{
					extendedMessage = fmt.Sprintf("%v %v=%v",extendedMessage,k,v)
				}

			case int:
				if(k == ResponseSizeStr){
					tmp := ResponseSize(x)
					responseSize = &tmp
				} else if(k == ResponseCodeStr){
					tmp := ResponseCode(x)
					responseCode = &tmp
				}else{
					extendedMessage = fmt.Sprintf("%v %v=%v",extendedMessage,k,v)
				}
			case int64:
				if(k == ResponseSizeStr){
					tmp := ResponseSize(x)
					responseSize = &tmp
				} else if(k == ResponseCodeStr){
					tmp := ResponseCode(x)
					responseCode = &tmp
				}else{
					extendedMessage = fmt.Sprintf("%v %v=%v",extendedMessage,k,v)
				}
			case *http.Request:
				httpReq = x
				loggingHttpReq = &logging.HttpRequest{
					Referer:       x.Referer(),
					RemoteIp:      x.RemoteAddr,
					RequestMethod: x.Method,
					RequestUrl:    x.URL.String(),
					UserAgent:     x.UserAgent(),
				}
			case ResponseSize:
				responseSize = &x
			case ResponseCode:
				responseCode = &x
			case ClientIP:
				clientIP = &x
			case LocalIP:
				localIP = &x
			case *logging.HttpRequest:
				loggingHttpReq = x

			case Latency:
				latency = &x

			case Trace:
				trace = &x
			case Label:
				labels[k] = fmt.Sprintf("%v", v)

			default:
				extendedMessage = fmt.Sprintf("%v %v=%v",k,v, extendedMessage)
			}
		}

		// write log entry
		if sh.fluentAgentClient != nil {
			sh.sendLogMessageViaAgentUsingFluent(entry, labels, loggingHttpReq)
		} else if(sh.defaultAgentLogger != nil){
			sh.sendLogMessageViaAgentUsingGoogleClient(entry,labels,httpReq,latency,trace,responseCode,responseSize, clientIP,localIP,extendedMessage)
		} else {
			sh.sendLogMessageViaAPI(entry, labels, loggingHttpReq)
		}
	}(sh.copyEntry(entry))

	return nil
}

func (sh *StackdriverHook) copyEntry(entry *logrus.Entry) *logrus.Entry {
	e := *entry
	e.Data = make(logrus.Fields, len(entry.Data))
	for k, v := range entry.Data {
		e.Data[k] = v
	}
	return &e
}

func (sh *StackdriverHook) sendLogMessageViaAgentUsingFluent(entry *logrus.Entry, labels map[string]string, httpReq *logging.HttpRequest) {
	// The log entry payload schema is defined by the Google fluentd
	// logging agent. See more at:
	// https://github.com/GoogleCloudPlatform/fluent-plugin-google-cloud
	logEntry := map[string]interface{}{
		"severity":         strings.ToUpper(entry.Level.String()),
		"timestampSeconds": strconv.FormatInt(entry.Time.Unix(), 10),
		"timestampNanos":   strconv.FormatInt(entry.Time.UnixNano()-entry.Time.Unix()*1000000000, 10),
		"message":          entry.Message,
	}
	for k, v := range labels {
		logEntry[k] = v
	}
	if httpReq != nil {
		logEntry["httpRequest"] = httpReq
	}
	// The error reporting payload JSON schema is defined in:
	// https://cloud.google.com/error-reporting/docs/formatting-error-messages
	// Which reflects the structure of the ErrorEvent type in:
	// https://godoc.org/google.golang.org/api/clouderrorreporting/v1beta1
	if sh.errorReportingServiceName != "" && isError(entry) {
		errorEvent := sh.buildErrorReportingEvent(entry, labels, httpReq)
		errorStructPayload, err := json.Marshal(errorEvent)
		if err != nil {
			log.Printf("error marshaling error reporting data: %s", err.Error())
		}
		var errorJSONPayload map[string]interface{}
		err = json.Unmarshal(errorStructPayload, &errorJSONPayload)
		if err != nil {
			log.Printf("error parsing error reporting data: %s", err.Error())
		}
		for k, v := range logEntry {
			errorJSONPayload[k] = v
		}
		if err := sh.fluentAgentClient.Post(sh.errorReportingLogName, errorJSONPayload); err != nil {
			log.Printf("error posting error reporting entries to logging agent: %s", err.Error())
		}
	} else {
		if err := sh.fluentAgentClient.Post(sh.logName, logEntry); err != nil {
			log.Printf("error posting log entries to logging agent: %s", err.Error())
		}
	}
}

//ignore keys of y if already exist on x
func unionLabels(x map[string]string,y map[string]string) *map[string]string{

	unionedMap := make(map[string]string)
	if y!= nil{
		for k, v := range y {
			unionedMap[k] = v
		}
	}
	if x!= nil {
		for k, v := range x {
			unionedMap[k] = v
		}
	}
	return &unionedMap

}


func (sh *StackdriverHook) sendLogMessageViaAgentUsingGoogleClient(entry *logrus.Entry, labels map[string]string, httpReq *http.Request,
	latency *Latency, trace *Trace, responseCode *ResponseCode,
	responseSize *ResponseSize, clientIP *ClientIP, localIP *LocalIP,extendedMessage string) {

	logEntry := googleLogging.Entry{}
	if(httpReq != nil){
		googleHttpRequest:= &googleLogging.HTTPRequest{Request:httpReq}
		if(latency != nil){
			googleHttpRequest.Latency = time.Duration(*latency)
		}
		if(clientIP != nil){
			googleHttpRequest.RemoteIP = string(*clientIP)
		}
		if(localIP!= nil){
			googleHttpRequest.LocalIP= string(*localIP)
		}
		if(responseCode != nil){
			googleHttpRequest.Status = int(*responseCode)
		}
		if(responseSize != nil){
			googleHttpRequest.ResponseSize = int64(*responseSize)
		}

		logEntry.HTTPRequest = googleHttpRequest
	}
	logEntry.Severity =logrusSeverityToGoogleAgentSeverity(entry.Level)

	logEntry.Labels = *unionLabels(labels,sh.defaultAgentLogger.labels)
	if(trace != nil ){
		logEntry.Trace = string(*trace)
	}
	message := fmt.Sprintf("%v %v",entry.Message,extendedMessage)
	logEntry.Payload = message
	sh.defaultAgentLogger.agentClientLogger.Log(logEntry)
	if sh.errorReportingServiceName != "" && isError(entry) {
		errorEntry := errorreporting.Entry{Error:errors.New(message)}
		if(httpReq!=nil){
			errorEntry.Req =httpReq
		}
		sh.defaultAgentLogger.errorreportingClient.Report(errorEntry)

	}
}

func logrusSeverityToGoogleAgentSeverity(level logrus.Level) googleLogging.Severity{

	var severity googleLogging.Severity
	if(logrus.PanicLevel == level){
		severity = googleLogging.Emergency
	} else if(logrus.FatalLevel == level){
		severity = googleLogging.Critical
	} else if(logrus.ErrorLevel == level){
		severity = googleLogging.Error
	} else if(logrus.WarnLevel == level){
		severity = googleLogging.Warning
	} else if(logrus.InfoLevel == level){
		severity = googleLogging.Info
	} else if(logrus.DebugLevel == level){
		severity = googleLogging.Debug
	}else{
		severity = googleLogging.Notice
	}
	return severity

}

func (sh *StackdriverHook) sendLogMessageViaAPI(entry *logrus.Entry, labels map[string]string, httpReq *logging.HttpRequest) {
	if sh.errorReportingServiceName != "" && isError(entry) {
		errorEvent := sh.buildErrorReportingEvent(entry, labels, httpReq)
		sh.errorService.Projects.Events.Report(sh.projectID, &errorEvent)
	} else {
		logName := sh.logName
		if sh.errorReportingLogName != "" && isError(entry) {
			logName = sh.errorReportingLogName
		}
		_, _ = sh.service.Write(&logging.WriteLogEntriesRequest{
			LogName:        logName,
			Resource:       sh.resource,
			Labels:         sh.labels,
			PartialSuccess: sh.partialSuccess,
			Entries: []*logging.LogEntry{
				{
					Severity:    strings.ToUpper(entry.Level.String()),
					Timestamp:   entry.Time.Format(time.RFC3339),
					TextPayload: entry.Message,
					Labels:      labels,
					HttpRequest: httpReq,
				},
			},
		}).Do()
	}
}



func (sh *StackdriverHook) buildErrorReportingEvent(entry *logrus.Entry, labels map[string]string, httpReq *logging.HttpRequest) clouderrorreporting.ReportedErrorEvent {
	errorEvent := clouderrorreporting.ReportedErrorEvent{
		EventTime: entry.Time.Format(time.RFC3339),
		Message:   entry.Message,
		ServiceContext: &clouderrorreporting.ServiceContext{
			Service: sh.errorReportingServiceName,
			Version: labels["version"],
		},
		Context: &clouderrorreporting.ErrorContext{
			User: labels["user"],
		},
	}
	// Assumes that caller stack frame information of type
	// github.com/facebookgo/stack.Frame has been added.
	// Possibly via a library like github.com/Gurpartap/logrus-stack
	if entry.Data["caller"] != nil {
		caller := entry.Data["caller"].(stack.Frame)
		errorEvent.Context.ReportLocation = &clouderrorreporting.SourceLocation{
			FilePath:     caller.File,
			FunctionName: caller.Name,
			LineNumber:   int64(caller.Line),
		}
	}
	if httpReq != nil {
		errRepHttpRequest := &clouderrorreporting.HttpRequestContext{
			Method:    httpReq.RequestMethod,
			Referrer:  httpReq.Referer,
			RemoteIp:  httpReq.RemoteIp,
			Url:       httpReq.RequestUrl,
			UserAgent: httpReq.UserAgent,
		}
		errorEvent.Context.HttpRequest = errRepHttpRequest
	}
	return errorEvent
}

func (sh *StackdriverHook) addCloseHandler(function func() error){
	sh.closeHandlers = append(sh.closeHandlers,function)
}

//flushing and closing connections
func (sh *StackdriverHook) Close() error{
	for _,x := range sh.closeHandlers{
		err := x()
		if err!= nil{
			return err
		}
	}
	return nil

}

