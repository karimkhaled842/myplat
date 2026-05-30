# myplat — DevSecOps control surface.
# Order for a clean run:  make hub ocm scanners pipeline deploy console
SHELL        := /bin/bash
PLATFORM     ?= /home/karim/appSecPlatform
KIND_CLUSTER ?= kind
SENTINEL_TOKEN ?= dev-sentinel-token
HUB_NS       := sentinel
export SENTINEL_TOKEN

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n",$$1,$$2}'

.PHONY: scanners
scanners: ## Install local scanners (bandit/semgrep/checkov via pip; trivy/gitleaks/grype expected on PATH)
	. $(PLATFORM)/.venv/bin/activate && pip install -q bandit semgrep checkov

# Helm release name `sentinel` => resources render as `sentinel-sentinel`.
HUB_SVC := sentinel-sentinel

.PHONY: hub
hub: ## Build hub image, load into kind, helm install into the sentinel namespace
	docker build -t sentinel-hub:local $(PLATFORM)
	kind load docker-image sentinel-hub:local --name $(KIND_CLUSTER)
	helm upgrade --install sentinel $(PLATFORM)/deploy/helm/sentinel \
	  -n $(HUB_NS) --create-namespace \
	  -f deploy/hub-values.yaml \
	  --set secret.apiToken=$(SENTINEL_TOKEN)
	kubectl -n $(HUB_NS) rollout status deploy/$(HUB_SVC) --timeout=180s
	@echo "Hub deployed. Port-forward with: make portforward"

.PHONY: portforward
portforward: ## Port-forward the in-cluster hub to localhost:8000 (background)
	@pkill -f "port-forward.*svc/$(HUB_SVC)" 2>/dev/null || true
	kubectl -n $(HUB_NS) port-forward svc/$(HUB_SVC) 8000:8000 > /tmp/sentinel-pf.log 2>&1 &
	@sleep 3 && curl -fsS http://127.0.0.1:8000/healthz && echo " <- hub reachable"

.PHONY: ocm
ocm: ## Build operator image, load into kind, apply OCM CRDs + operator
	docker build -t sentinel-operator:local $(PLATFORM)/ocm_operator
	kind load docker-image sentinel-operator:local --name $(KIND_CLUSTER)
	bash pipeline/ocm-deploy.sh

.PHONY: pipeline
pipeline: ## Run the full 18-stage DevSecOps pipeline against the hub
	bash pipeline/run.sh

.PHONY: deploy
deploy: ## Stage 18: build+load app image, push repo, ArgoCD sync, trivy-k8s live scan
	bash pipeline/deploy.sh

.PHONY: console
console: ## Run the SentinelSDLC PatternFly console at http://127.0.0.1:5173
	cd $(PLATFORM)/frontend && npm install && npm run dev

.PHONY: clean
clean: ## Remove generated artifacts
	rm -rf artifacts tasks.db
