#!/usr/bin/env bash
# Kubernetes e2e for the auth callout's projected service-account-token support.
#
# Spins up a kind cluster, builds + loads the callout image, deploys NATS (with
# auth_callout) and the callout (configured to verify the in-cluster Kubernetes
# OIDC issuer via the cluster CA, see manifests/02-callout.yaml), then runs two
# client jobs:
#   - nats-client SA  -> policy grants APP, publish must succeed
#   - default SA      -> no policy rule, connection must be denied
#
# Usage:
#   test/k8s/run.sh            # create cluster (if needed), deploy, assert
#   test/k8s/run.sh --cleanup  # same, then delete the cluster on success
#
# Requires: docker, kind, kubectl.
set -euo pipefail

CLUSTER="${CLUSTER:-nats-callout-e2e}"
# Pin the node image: kind v0.32.0's default (kindest/node:v1.36.1) currently
# ships a broken arm64 variant ("exec format error"). v1.34.0 is multi-arch and
# healthy. Override with NODE_IMAGE= if a newer default works for you.
NODE_IMAGE="${NODE_IMAGE:-kindest/node:v1.34.0}"
IMG="${IMG:-nats-jwt-callout:e2e}"
CLIENT_IMG="${CLIENT_IMG:-nats-jwt-callout-k8s-client:e2e}"
CTX="kind-${CLUSTER}"
NS="nats-callout-e2e"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MANIFESTS="${SCRIPT_DIR}/manifests"

CLEANUP=0
[ "${1:-}" = "--cleanup" ] && CLEANUP=1

k() { kubectl --context "${CTX}" "$@"; }

echo ">> ensuring kind cluster ${CLUSTER} (node ${NODE_IMAGE})"
if ! kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
  kind create cluster --name "${CLUSTER}" --image "${NODE_IMAGE}" --wait 90s
fi

# SKIP_BUILD=1 lets a caller (e.g. CI) build ${IMG} beforehand -- with a layer
# cache -- and have this script just load the pre-built image.
if [ "${SKIP_BUILD:-0}" = "1" ]; then
  echo ">> skipping image build (SKIP_BUILD=1); using pre-built ${IMG} and ${CLIENT_IMG}"
else
  echo ">> building callout image ${IMG}"
  docker build -t "${IMG}" -f "${SCRIPT_DIR}/Dockerfile" "${REPO_ROOT}"
  echo ">> building client image ${CLIENT_IMG}"
  docker build -t "${CLIENT_IMG}" -f "${SCRIPT_DIR}/client.Dockerfile" "${REPO_ROOT}"
fi

echo ">> loading images into kind"
kind load docker-image "${IMG}" "${CLIENT_IMG}" --name "${CLUSTER}"

echo ">> applying manifests"
k apply -f "${MANIFESTS}/00-setup.yaml" \
        -f "${MANIFESTS}/01-nats.yaml" \
        -f "${MANIFESTS}/02-callout.yaml"

echo ">> waiting for NATS and callout rollouts"
k -n "${NS}" rollout status deploy/nats --timeout=120s
k -n "${NS}" rollout status deploy/nats-callout --timeout=120s

echo ">> running client jobs"
# Jobs are immutable, so drop any from a previous run before re-applying.
k delete -f "${MANIFESTS}/03-client.yaml" --ignore-not-found --wait=true >/dev/null 2>&1 || true
k apply -f "${MANIFESTS}/03-client.yaml"

# Wait for each job to reach a terminal state, then assert it is the right one.
assert_job() {
  local job="$1" want="$2" # want = complete|failed
  local other; [ "${want}" = complete ] && other=failed || other=complete
  # Race the two terminal conditions; whichever fires first wins.
  if k -n "${NS}" wait --for="condition=${want}" "job/${job}" --timeout=120s >/dev/null 2>&1; then
    echo "   PASS ${job} (${want})"
    return 0
  fi
  echo "   FAIL ${job}: did not reach '${want}'"
  k -n "${NS}" get "job/${job}" -o wide || true
  k -n "${NS}" logs -l "app=${job}" --tail=50 || true
  return 1
}

rc=0
assert_job nats-client-allow complete || rc=1
assert_job nats-client-deny  complete || rc=1

echo ">> client logs"
echo "-- allow --"; k -n "${NS}" logs -l app=nats-client-allow --tail=20 || true
echo "-- deny  --"; k -n "${NS}" logs -l app=nats-client-deny  --tail=20 || true

if [ "${rc}" -ne 0 ]; then
  echo ">> callout logs (for debugging)"
  k -n "${NS}" logs deploy/nats-callout --tail=80 || true
  echo "E2E FAILED"
  exit 1
fi

echo "E2E PASSED"
if [ "${CLEANUP}" -eq 1 ]; then
  echo ">> deleting cluster ${CLUSTER}"
  kind delete cluster --name "${CLUSTER}"
fi
