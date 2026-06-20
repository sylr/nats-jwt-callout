# goreleaser (dockers_v2) builds the per-platform binary and stages it under
# <TARGETPLATFORM>/ in the build context; this image only packages it.
FROM gcr.io/distroless/static:nonroot
ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/nats-oidc-callout /usr/bin/nats-oidc-callout
ENTRYPOINT ["/usr/bin/nats-oidc-callout"]
