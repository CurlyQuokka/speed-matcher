MAIN_PATH=cmd/speed-matcher/speed-matcher.go
IMAGE_NAME=speed-matcher
IMAGE_TAG=latest
MATCHER_SECRET=defaultSecret16B

build:
	go build -o bin/speed-matcher $(MAIN_PATH)

run:
	go run $(MAIN_PATH)

clean:
	rm -rf bin 2> /dev/null

docker-build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

lint:
	golangci-lint run
