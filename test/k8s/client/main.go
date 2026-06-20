// Command k8s-client is the Kubernetes e2e client. It reads a projected
// service-account token via lib/k8sauth and connects to NATS to publish a
// message, exercising the auth-callout flow end to end.
//
// With -expect allow, a successful publish is the pass condition. With
// -expect deny, a denied connection is the pass condition (the deny job runs as
// a service account no policy rule matches). This single binary therefore backs
// both the allow and deny jobs, no shell required (the image is distroless).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/sylr/nats-oidc-callout/lib/k8sauth"
)

func main() {
	url := flag.String("url", "nats://nats:4222", "NATS server URL")
	tokenPath := flag.String("token-path", "/var/run/secrets/nats/token", "projected service-account token path")
	subject := flag.String("subject", "app.test", "subject to publish to")
	expect := flag.String("expect", "allow", "expected outcome: allow|deny")
	flag.Parse()

	if *expect != "allow" && *expect != "deny" {
		log.Fatalf("invalid -expect %q (want allow|deny)", *expect)
	}

	if err := run(*url, *tokenPath, *subject, *expect); err != nil {
		log.Fatalf("%v", err)
	}
}

func run(url, tokenPath, subject, expect string) error {
	ts, err := k8sauth.New(k8sauth.Config{TokenPath: tokenPath})
	if err != nil {
		return err
	}

	// Pre-read the token so a token-source problem (missing/empty file) is a hard
	// failure in both modes, never mistaken for an authorization denial below.
	if _, err := ts.Token(context.Background()); err != nil {
		return err
	}

	// MaxReconnects(0): this is a one-shot job, not a long-lived connection, so
	// there is no refresh cycle to honour here.
	nc, err := nats.Connect(url,
		ts.NATSOption(),
		nats.MaxReconnects(0),
		nats.Timeout(5*time.Second),
	)
	if err != nil {
		// Only an authorization violation is the expected denial; transport or
		// setup failures (DNS, server down, timeout) must fail the test rather
		// than masquerade as a successful denial.
		if expect == "deny" && errors.Is(err, nats.ErrAuthorization) {
			fmt.Println("DENIED_AS_EXPECTED")
			return nil
		}
		return fmt.Errorf("connect: %w", err)
	}
	defer nc.Close()

	if expect == "deny" {
		return fmt.Errorf("connected but expected denial")
	}

	if err := nc.Publish(subject, []byte("hello from k8s e2e")); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	if err := nc.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	fmt.Println("PUBLISH_OK")
	return nil
}
