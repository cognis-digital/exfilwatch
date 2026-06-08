# Deploying exfilwatch

`exfilwatch` ships a container and is deployable to any cloud or orchestrator.

| Target | How |
|---|---|
| **Docker Compose** | `docker compose -f deploy/docker-compose.yml up -d` |
| **Kubernetes** | `kubectl apply -f deploy/k8s.yaml` |
| **Terraform** | `cd deploy/terraform && terraform init && terraform apply` |
| **AWS** | ECS Fargate / App Runner / Lambda (container image) from `ghcr.io/cognis-digital/exfilwatch` |
| **Azure** | Container Apps / ACI: `az containerapp create --image ghcr.io/cognis-digital/exfilwatch` |
| **GCP** | Cloud Run: `gcloud run deploy exfilwatch --image ghcr.io/cognis-digital/exfilwatch` |
| **Fly.io / Render / Railway** | point at the Dockerfile |

CI publishes the image to GHCR on tag push (`.github/workflows/docker-publish.yml`).
