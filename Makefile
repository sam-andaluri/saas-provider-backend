all: docker k8ibm

.PHONY: all

docker:
	docker build -t saas-provider-backend:latest .
	docker tag saas-provider-backend:latest sandaluri/saas-provider-backend:latest
	docker push sandaluri/saas-provider-backend:latest
k8ibm:
	kubectl create secret generic provider-backend -n saas-provider-backend --from-literal=GITHUB_TOKEN=dummy --from-literal=GITHUB_USER=dummy --from-literal=GITHUB_TEMPLATED_REPO=dummy
	kustomize build kubernetes/overlays/ibm | kubectl apply -f -
