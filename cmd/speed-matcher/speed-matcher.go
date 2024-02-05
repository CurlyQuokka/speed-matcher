package main

import (
	"log"

	"github.com/CurlyQuokka/speed-matcher/pkg/config"
	"github.com/CurlyQuokka/speed-matcher/pkg/security"
	"github.com/CurlyQuokka/speed-matcher/pkg/server"
)

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

	s := server.New(cfg.MaxUploadSize, cfg.AllowedDomains, sec)

	err = s.Serve(cfg.Port)
	if err != nil {
		log.Fatalf("error in HTTP server: %s\n", err.Error())
	}

	otpWatchQuit <- true
}
