package main

import (
	"errors"
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

func main() {
	cfg, err := config.FromEnv()
	if err != nil {
		log.Fatalf("cannot create config from env: %s\n", err.Error())
	}

	otpWatchQuit := make(chan bool)
	defer close(otpWatchQuit)

	sec, err := security.New(cfg.Secret, cfg.AllowedDomains, otpWatchQuit)
	if err != nil {
		log.Fatalf("cannot create security module: %s\n", err.Error())
	}

	srv := server.New(cfg.MaxUploadSize, sec, cfg.CertFile, cfg.KeyFile)

	serverErrors := make(chan error, 1)
	go srv.Serve(cfg.Port, serverErrors)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	for {
		select {
		case err = <-serverErrors:
			otpWatchQuit <- true
			if !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("error in HTTP server: %s", err.Error())
			}
			<-otpWatchQuit
			return
		case <-quit:
			log.Print("OS interrupt received. Server will shut down in 5s")
			otpWatchQuit <- true

			if err = srv.Shutdown(); err != nil {
				log.Fatalf("error closing server: %s", err.Error())
			}

			<-otpWatchQuit
			return
		default:
			time.Sleep(sleepTime)
		}
	}
}
