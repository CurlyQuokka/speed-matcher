MAIN_PATH=cmd/speed-matcher/speed-matcher.go

build:
	go build -o bin/speed-matcher $(MAIN_PATH)

run:
	go run $(MAIN_PATH)