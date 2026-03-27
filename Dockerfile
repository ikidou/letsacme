# syntax=docker/dockerfile:1

## -----------------------------------------------------
## Using a dev image for the build stage (e.g., 1.22-dev)
FROM dhi.io/golang:1.26.1 AS build-stage

WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /app/letsacme

## -----------------------------------------------------
## Using a dhi-static image for the runtime
FROM dhi.io/static:20250419-debian13 AS runtime-stage

COPY --from=build-stage /app/letsacme /letsacme
WORKDIR /data
VOLUME /data
EXPOSE 3000
ENTRYPOINT ["/letsacme"]
