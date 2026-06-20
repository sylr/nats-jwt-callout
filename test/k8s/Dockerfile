# Build image for the k8s e2e (kind). Unlike the release Dockerfile (which
# consumes goreleaser's pre-staged binary), this compiles from source.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/nats-jwt-callout ./cmd/nats-jwt-callout

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/nats-jwt-callout /usr/bin/nats-jwt-callout
ENTRYPOINT ["/usr/bin/nats-jwt-callout"]
