app ?= relay
# Env name that can be passed as an argument
env ?= prod
# Deployment region
region ?= us-east-2

# Grab the current user for the default username
username ?= $(USER)

# AWS account and profile for the environment
profile ?= prod
# ECR registry in staging account
registry ?= 235487987553.dkr.ecr.$(region).amazonaws.com

# Get the Git commit hash to use as an image tag
commit_hash := $(shell git rev-parse --short HEAD)

.PHONY: copilot-app-init
copilot-app-init: ## Init Copilot app
	AWS_PROFILE=$(profile) AWS_REGION=${region} copilot app init ${app} --resource-tags Env=${env},User=${username} --domain aws.border0.com

.PHONY: copilot-app-delete
copilot-app-delete: ## Delete Copilot app
	AWS_PROFILE=$(profile) AWS_REGION=${region} copilot app delete --name ${app}

.PHONY: copilot-prod-env-init
copilot-prod-env-init: ## Init Copilot environment
	AWS_PROFILE=$(profile) AWS_REGION=${region} copilot env init --app ${app} --profile prod --name prod-${region} \
		--region $(region) --import-vpc-id vpc-0d32a86a790e2a782 \
		--import-public-subnets subnet-03efe58326bd24e45,subnet-0c0eb1bb4d64951d7 \
		--import-private-subnets subnet-0bd21f553b89af6f5,subnet-021170e4067ff30bc

.PHONY: copilot-staging-env-init
copilot-staging-env-init: ## Init Copilot environment
	AWS_PROFILE=$(profile) AWS_REGION=${region} copilot env init --app ${app} --profile staging --name staging-${region} \
		--region $(region) --import-vpc-id vpc-0fa87fe82ca8cd823 \
		--import-public-subnets subnet-06660942fb02b7209,subnet-0b5dfdeb542a4bd86 \
		--import-private-subnets subnet-002e0be7f0c7dc01b,subnet-041ac9a611c97ae37 

.PHONY: copilot-prod-env-deploy
copilot-prod-env-deploy: ## Deploy Copilot multi-region env
	AWS_PROFILE=$(profile) AWS_REGION=${region} copilot env deploy --app ${app} --name prod-$(region) --force

.PHONY: copilot-staging-env-deploy
copilot-staging-env-deploy: ## Deploy Copilot multi-region env
	AWS_PROFILE=$(profile) AWS_REGION=${region} copilot env deploy --app ${app} --name staging-$(region) --force


.PHONY: copilot-svc-init
copilot-svc-init: ## Init Copilot service
	AWS_PROFILE=$(profile) AWS_REGION=${region} copilot svc init \
	--svc-type 'Load Balanced Web Service' \
	--app ${app} --name ${app} --port 80 \
	--dockerfile './Dockerfile'

.PHONY: gh-deploy-svc-prod
gh-deploy-svc-prod: ## Deploy the service to the prod environment
	DOCKER_REGISTRY=$(registry) AWS_REGION=${region} \
	copilot svc deploy --env prod-$(region) --app ${app} --name ${app} --resource-tags Env=${env},User=${username} --force

.PHONY: gh-deploy-svc-staging
gh-deploy-svc-staging: ## Deploy the service to the staging environment
	DOCKER_REGISTRY=$(registry) AWS_REGION=${region} \
	copilot svc deploy --env staging-$(region) --app ${app} --name ${app} --resource-tags Env=${env},User=${username} --force


.PHONY: deploy-svc-prod
deploy-svc-prod: ## Deploy the service to the prod environment
	DOCKER_REGISTRY=$(registry) AWS_PROFILE=$(profile) AWS_REGION=${region} \
	copilot svc deploy --env prod-$(region) --app ${app} --name ${app} --resource-tags Env=${env},User=${username} --force

.PHONY: deploy-svc-staging
deploy-svc-staging: ## Deploy to staging environment
	DOCKER_REGISTRY=$(registry) AWS_PROFILE=$(profile) AWS_REGION=${region} \
	copilot svc deploy --env staging-$(region) --app ${app} --name ${app} --resource-tags Env=${env},User=${username} --force


.PHONY: re-deploy-svc-prod
re-deploy-svc-prod: copilot-prod-env-deploy copilot-svc-init deploy-svc-prod ## De-deploy end and svc to prod environment

.PHONY: re-deploy-svc-staging
re-deploy-svc-staging: copilot-staging-env-deploy copilot-svc-init deploy-svc-staging ## De-deploy end and svc to staging environment


.PHONY: re-deploy-prod
re-deploy-prod: copilot-prod-env-init copilot-prod-env-deploy copilot-svc-init deploy-svc-prod ## Re-deploy and re init the env and service in the prod environment

.PHONY: re-deploy-staging
re-deploy-staging: copilot-staging-env-init copilot-staging-env-deploy copilot-svc-init deploy-svc-staging ## Re-deploy and re init the env and service in the staging environment



.PHONY: copilot-staging-env-delete
copilot-staging-env-delete: ## Delete Copilot staging environment
	AWS_PROFILE=$(profile) AWS_REGION=$(region) copilot env delete --app $(app) --name staging-$(region) --yes

.PHONY: copilot-prod-env-delete
copilot-prod-env-delete: ## Delete Copilot prod environment
	AWS_PROFILE=$(profile) AWS_REGION=$(region) copilot env delete --app $(app) --name prod-$(region) --yes


.PHONY: copilot-svc-delete
copilot-svc-delete: ## Destroy Copilot service
	AWS_PROFILE=$(profile) AWS_REGION=${region} copilot svc delete --app ${app} --name ${app} --yes

.PHONY: destroy-svc-prod
destroy-svc-prod: ## Destroy the service in the prod environment
	AWS_PROFILE=$(profile) AWS_REGION=${region} \
	copilot svc delete --env prod-$(region) --app ${app} --name ${app} --yes

.PHONY: destroy-svc-staging
destroy-svc-staging: ## Destroy the service in the staging environment
	AWS_PROFILE=$(profile) AWS_REGION=${region} \
	copilot svc delete --env staging-$(region) --app ${app} --name ${app} --yes

.PHONY: build ## Build the WebSocket server binary
build: ## Ensure that the binary is built before deploying
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o server_ws cmd/server_ws/main.go

.PHONY: build-client ## Build the TURTLE client binary for a the local OS and architecture
build-client:
	go build -o client ./cmd/client_ws_simple

.PHONY: build-client-wasm ## Build the TURTLE client binary for a wasm target
build-client-wasm:
	GOOS=js GOARCH=wasm go build -o client_wasm ./cmd/client_ws_simple

.PHONY: push
push: ## Push docker image to AWS ECR. Usage: make push [env=staging|prod]
	aws ecr get-login-password --profile $(profile) --region $(region) | docker login --username AWS --password-stdin $(registry)
	docker push ${registry}/${app}/${app}

.PHONY: build-docker
build-docker: ## Build the Docker image. Usage: make build-docker [env=staging|prod]
	docker build -t ${registry}/${app}/${app} -f Dockerfile .
