FROM golang:1.21 AS build-env

WORKDIR /src

COPY . ./

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -o /speed-matcher cmd/speed-matcher/speed-matcher.go

FROM scratch
WORKDIR /src

COPY --from=build-env /speed-matcher /
COPY --from=build-env /src/frontend /src/frontend/
COPY --from=build-env /src/templates /src/templates/

CMD ["/speed-matcher"]
