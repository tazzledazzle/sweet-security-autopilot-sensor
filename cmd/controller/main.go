package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/tazzledazzle/sweet-security-autopilot-sensor/internal/config"
	"github.com/tazzledazzle/sweet-security-autopilot-sensor/internal/controller"
	"github.com/tazzledazzle/sweet-security-autopilot-sensor/internal/server"
)

func main() {
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetLevel(logrus.InfoLevel)

	cfg := config.DefaultControllerConfig()
	ctrl := controller.New(cfg, log)
	ctrl.Start(context.Background())

	srv := server.New(cfg, ctrl, log)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("Controller server failed")
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info("Shutting down controller")
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
