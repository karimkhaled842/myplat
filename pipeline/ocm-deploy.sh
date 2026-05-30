#!/usr/bin/env bash
# Deploy the SentinelSDLC OCM CRDs + operator into the kind cluster.
# The operator runs in `sentinel-system`; the hub Service lives in `sentinel`,
# so we point it at the cross-namespace FQDN and use the kind-loaded local image.
set -uo pipefail
PLATFORM="${PLATFORM:-/home/karim/appSecPlatform}"
TOKEN="${SENTINEL_TOKEN:-dev-sentinel-token}"

kubectl create namespace sentinel-system --dry-run=client -o yaml | kubectl apply -f -

# The operator reads token from secret `sentinel-secret` (key SENTINEL_API_TOKEN).
kubectl -n sentinel-system create secret generic sentinel-secret \
  --from-literal=SENTINEL_API_TOKEN="$TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -

# CRDs (cluster-scoped) + RBAC + operator Deployment.
kubectl apply -k "$PLATFORM/deploy/ocm"

# Override the never-published ghcr image with our kind-loaded local build,
# never pull, and target the hub in the `sentinel` namespace.
kubectl -n sentinel-system patch deploy sentinel-operator --type=merge -p '{
  "spec":{"template":{"spec":{"containers":[{
    "name":"operator","image":"sentinel-operator:local","imagePullPolicy":"Never"}]}}}}'
# Helm renders the hub Service as `sentinel-sentinel` in the `sentinel` namespace.
kubectl -n sentinel-system set env deploy/sentinel-operator \
  SENTINEL_API_URL=http://sentinel-sentinel.sentinel.svc.cluster.local:8000

kubectl -n sentinel-system rollout status deploy/sentinel-operator --timeout=120s || true
echo "OCM CRDs:"; kubectl get crds | grep sentinel.io || true
echo "Operator:"; kubectl get pods -n sentinel-system
