# goreleaser builds the binary and provides it in the build context; this image
# only packages it.
FROM gcr.io/distroless/static:nonroot
COPY nats-jwt-callout /usr/bin/nats-jwt-callout
ENTRYPOINT ["/usr/bin/nats-jwt-callout"]
