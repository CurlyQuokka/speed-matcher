package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/CurlyQuokka/speed-matcher/pkg/config"
	"github.com/CurlyQuokka/speed-matcher/pkg/security"
	"github.com/CurlyQuokka/speed-matcher/pkg/server"
)

const sleepTime = time.Second * 2

func start() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return fmt.Errorf("cannot create config from env: %w", err)
	}

	otpWatchQuit := make(chan bool)
	defer close(otpWatchQuit)

	sec, err := security.New(cfg.Secret, cfg.AllowedDomains, otpWatchQuit)
	if err != nil {
		return fmt.Errorf("cannot create security module: %w", err)
	}

	srv, err := server.New(sec, cfg)
	if err != nil {
		return fmt.Errorf("cannot create server: %w", err)
	}

	serverErrors := make(chan error, 1)
	go srv.Serve(cfg.Port, serverErrors)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	for {
		select {
		case err = <-serverErrors:
			otpWatchQuit <- true
			if !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("error in HTTP server: %w", err)
			}
			<-otpWatchQuit
			return err
		case <-quit:
			log.Printf("OS interrupt received. Server will shut down in %s", server.DefaultShutdownTimeout.String())
			otpWatchQuit <- true
			<-otpWatchQuit

			if err = srv.Shutdown(); err != nil {
				return fmt.Errorf("error closing server: %w", err)
			}

			return nil
		default:
			time.Sleep(sleepTime)
		}
	}
}

func main() {
	if err := start(); err != nil {
		log.Printf("error: %s", err.Error())
		os.Exit(1)
	}
}
