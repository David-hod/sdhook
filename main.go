package main

import (
	"time"

	"github.com/sirupsen/logrus"
	"context"
	"net/http/httptest"
	"github.com/David-hod/sdhook/hook"
)
//
//func main() {
//	// create a logger with some fields
//	logger := logrus.New()
//	logger.WithFields(logrus.Fields{
//		"my_field":  115888,
//		"my_field2": 898858,
//	})
//
//	// create stackdriver hook
//	hook, err := sdhook.New(
//		sdhook.GoogleServiceAccountCredentialsFile("./credentials.json"),
//		sdhook.LogName("some_log"),
//	)
//	if err != nil {
//		logger.Fatal(err)
//	}
//
//	// add to logrus
//	logger.Hooks.Add(hook)
//
//	// log some message
//	logger.Printf("a random message @ %s", time.Now().Format("15:04:05"))
//
//	// wait for the writes to finish
//	time.Sleep(10 * time.Second)
//}

func main() {
	// create a logger with some fields
	level,err :=logrus.ParseLevel("debug")
	projectID := "yolion-production"
	service := "drogowebservice"
	errorService := "drogowebservice"
	reqlogName := "req"
	appLogName := "app"
	ctx := context.Background()
	labels :=map[string]string{
		"app":  service,
	}
	resourceType := "gce_instance"
	reqHook,err := sdhook.New(sdhook.GoogleLoggingAgent(projectID, service, &errorService,reqlogName, ctx, labels, resourceType))
	if(err!= nil){
		println("couldn't create reqHook. "+err.Error())
	}

	appHook,err := sdhook.New(sdhook.GoogleLoggingAgent(projectID, service, &errorService,appLogName, ctx, labels, resourceType))
	if(err!= nil){
		println("couldn't create appHook. "+err.Error())
	}
	mockReq := httptest.NewRequest("Get", "/src/main", nil)
	logrus.SetFormatter(&logrus.TextFormatter{})
	reqLogger := logrus.New()
	reqLogger.SetLevel(level)
	reqLogger.AddHook(reqHook)

	appLogger := logrus.New()
	appLogger.SetLevel(level)
	appLogger.AddHook(appHook)

	responseSize := sdhook.ResponseSize(50)
	responseCode := sdhook.ResponseCode(200)
	clientIP := sdhook.ClientIP("10.5.5.5")
	localIP := sdhook.LocalIP("1.1.1.1")
	latency := sdhook.Latency(time.Second*5)
	trace := sdhook.Trace("my-trace")
	//"responseSize":  responseSize,
	//	"responseCode":  responseCode,
	fields := map[string]interface{}{
		"trace": trace,
		"latency" : latency,
		"localIP" : localIP,
		"clientIP": clientIP,

	}

	reqLoggerWithFields := reqLogger.WithFields(fields).WithField("request", mockReq).WithField("responseSize", responseSize).WithField("responseCode", responseCode).WithField("label:label1","hello").WithField("label:label2","hello2")
	reqLoggerWithFields.Info("new request")

	appLoggerWithFields := appLogger.WithFields(fields)
	appLoggerWithFields.Info("Alice: Bob you ate my pizza")
	appLoggerWithFields.Info("Bob: No I didn't")
	appLoggerWithFields.Error("Alice: Bob you are lier")


	// wait for the writes to finish
	time.Sleep(10 * time.Second)
	reqHook.Close()
	appHook.Close()
}
