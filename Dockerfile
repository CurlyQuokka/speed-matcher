FROM golang:1.21

WORKDIR /src

COPY . ./

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -o /speed-matcher cmd/speed-matcher/speed-matcher.go

CMD ["/speed-matcher"]
