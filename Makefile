MAIN_PATH=cmd/speed-matcher/speed-matcher.go
IMAGE_NAME=speed-matcher
REPO=ghcr.io/curlyquokka
IMAGE_TAG=contact-v6

build:
	go build -o bin/speed-matcher $(MAIN_PATH)

run:
	go run $(MAIN_PATH)

clean:
	rm -rf bin 2> /dev/null

docker-build:
	docker build -t $(REPO)/$(IMAGE_NAME):$(IMAGE_TAG) .
# 	docker push $(REPO)/$(IMAGE_NAME):$(IMAGE_TAG)

lint:
	golangci-lint run
