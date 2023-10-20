package main

import (
	"context"
	"fmt"
	"github.com/compliance-framework/configuration-service/internal/adapter/api"
	"github.com/compliance-framework/configuration-service/internal/adapter/store/mongo"
	"github.com/compliance-framework/configuration-service/internal/domain/service"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup

	mongoUri := getEnvironmentVariable("MONGO_URI", "mongodb://mongo:27017")

	logger, err := zap.NewProduction()
	if err != nil {
		log.Fatalf("Can't initialize zap logger: %v", err)
	}
	sugar := logger.Sugar()

	err = mongo.Connect(ctx, mongoUri, "cf")
	if err != nil {
		sugar.Fatalf("error connecting to mongo: %v", err)
	}

	server := api.NewServer(ctx)
	controlService := service.NewControlService()
	controlHandler := api.NewControlHandler(controlService)
	server.Route("GET", "/controls/:id", controlHandler.GetControl)

	wg.Add(1)
	go func() {
		defer wg.Done()
		checkErr(server.Start(":8080"))
	}()

	<-ctx.Done()

	sugar.Info("shutting down control-plane")
	err = server.Stop()
	sugar.Info("control-plane shut down")
	if err != nil {
		sugar.Errorf("error shutting down server: %v", err)
	}

	err = mongo.Disconnect()
	if err != nil {
		sugar.Errorf("error disconnecting from mongo: %v", err)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		fmt.Println("control-plane shut down.")
	case <-time.After(5 * time.Second):
		fmt.Println("timed out waiting for components to shut down; exiting anyway.")
	}

	os.Exit(0)
}

func getEnvironmentVariable(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}

func checkErr(err error) {
	if err != nil {
		log.Fatalf("An error occurred: %v", err)
	}
}
