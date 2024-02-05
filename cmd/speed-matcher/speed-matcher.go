package main

import (
	"log"

	"github.com/CurlyQuokka/speed-matcher/pkg/config"
	"github.com/CurlyQuokka/speed-matcher/pkg/security"
	"github.com/CurlyQuokka/speed-matcher/pkg/server"
)

func main() {
	var err error

	cfg, err := config.FromEnv()
	if err != nil {
		log.Fatalf("cannot create secret from env: %s", err.Error())
	}

	otpWatchQuit := make(chan bool)
	defer close(otpWatchQuit)

	sec, err := security.New(cfg.Secret, otpWatchQuit)
	if err != nil {
		log.Fatalf("cannot create security module: %s", err.Error())
	}

	s := server.New(cfg.MaxUploadSize, cfg.AllowedDomains, sec)

	err = s.Serve(cfg.Port)
	if err != nil {
		log.Fatal(err)
	}

	otpWatchQuit <- true
}
