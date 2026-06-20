#!/bin/sh
# Create the system user/group the service runs as. Runs before files are
# unpacked (deb preinst / rpm %pre), so file ownership set by the package
# applies cleanly.
set -e

if ! getent group nats-oidc-callout >/dev/null 2>&1; then
    groupadd --system nats-oidc-callout
fi

if ! getent passwd nats-oidc-callout >/dev/null 2>&1; then
    useradd --system --gid nats-oidc-callout \
        --home-dir /nonexistent --no-create-home \
        --shell /usr/sbin/nologin \
        --comment "NATS auth callout service" \
        nats-oidc-callout
fi
