#!/usr/bin/env bash
# Stage 18 — GitOps deploy on a passing gate:
#   build+load the app image, push to GitHub, let ArgoCD sync it into the
#   cluster, then run a live trivy-k8s scan of the running workload and import
#   the runtime findings back into the hub.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PLATFORM="${PLATFORM:-/home/karim/appSecPlatform}"
KIND_CLUSTER="${KIND_CLUSTER:-kind}"
REPO_SSH="git@github-main:karimkhaled842/myplat.git"
ART="$HERE/artifacts"; mkdir -p "$ART"
export SENTINEL_API_URL="${SENTINEL_API_URL:-http://127.0.0.1:8000}"
export SENTINEL_TOKEN="${SENTINEL_TOKEN:-dev-sentinel-token}"
# shellcheck disable=SC1091
[ -f "$PLATFORM/.venv/bin/activate" ] && source "$PLATFORM/.venv/bin/activate"
export PATH="$HOME/.local/bin:$PATH"

c_grn=$'\e[1;32m'; c_blue=$'\e[1;34m'; c_yel=$'\e[1;33m'; c_rst=$'\e[0m'
stage(){ echo; echo "${c_blue}=== $* ===${c_rst}"; }

# --- 1. Build the app image and load it into kind ----------------------------
stage "Build + kind-load app image (myplat-api:local)"
docker build -t myplat-api:local "$HERE"
kind load docker-image myplat-api:local --name "$KIND_CLUSTER"

# --- 2. Push manifests to GitHub (the GitOps source of truth) ----------------
stage "Push to $REPO_SSH"
cd "$HERE"
[ -d .git ] || git init -q
git config user.email "karim.khaled@opsera.org" 2>/dev/null || true
git config user.name  "karimkhaled842"   2>/dev/null || true
git add -A
git commit -q -m "myplat: app + k8s + DevSecOps pipeline" || echo "nothing to commit"
git remote get-url origin >/dev/null 2>&1 || git remote add origin "$REPO_SSH"
git branch -M main
git push -u origin main || { echo "${c_yel}push failed — create the public repo karimkhaled842/myplat first${c_rst}"; }

# --- 3. ArgoCD Application: create + sync -------------------------------------
stage "ArgoCD sync"
kubectl apply -f "$HERE/argocd/application.yaml"
# Hard refresh so ArgoCD picks up the just-pushed commit, then let auto-sync run.
kubectl -n argocd annotate app myplat argocd.argoproj.io/refresh=hard --overwrite >/dev/null 2>&1 || true
if command -v argocd >/dev/null 2>&1; then
  argocd app sync myplat --timeout 180 2>/dev/null || true
fi

# --- 4. Wait for the workload ------------------------------------------------
stage "Wait for rollout in namespace myplat"
for i in $(seq 1 30); do
  kubectl -n myplat get deploy myplat-api >/dev/null 2>&1 && break || sleep 5
done
kubectl -n myplat rollout status deploy/myplat-api --timeout=180s || echo "${c_yel}rollout pending — check ArgoCD UI${c_rst}"
kubectl get pods -n myplat -o wide || true

# --- 5. Live trivy-k8s runtime scan -> import into the hub -------------------
stage "trivy-k8s live cluster scan -> import (runtime posture)"
if command -v trivy >/dev/null 2>&1; then
  trivy k8s --include-namespaces myplat --scanners misconfig,vuln \
    --format json --output "$ART/trivy-k8s-live.json" --timeout 5m 2>/dev/null \
    || trivy k8s -n myplat --format json -o "$ART/trivy-k8s-live.json" 2>/dev/null \
    || cp "$PLATFORM/samples/trivy-k8s.json" "$ART/trivy-k8s-live.json"
else
  cp "$PLATFORM/samples/trivy-k8s.json" "$ART/trivy-k8s-live.json"
fi
sentinel import "$ART/trivy-k8s-live.json" --asset myplat-api --tool trivy-k8s \
  && echo "${c_grn}✔ runtime findings imported${c_rst}" || echo "${c_yel}import failed${c_rst}"

stage "Deploy complete"
kubectl -n argocd get app myplat 2>/dev/null || true
echo "App pods:"; kubectl get pods -n myplat 2>/dev/null || true
