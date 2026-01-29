# Enterprise Deployment Options

1. **CLI Mode** (default) – Run directly on endpoints or servers
2. **CI/CD Integration** – Add to model upload pipelines
   Example GitHub Action / Jenkins step:
   ```yaml
   - name: Scan PyTorch models
     run: python cyberdudebivash-op-model-sentry.py --dir models/ --json > scan-report.json

API Mode (coming in v1.1) – FastAPI endpoint for internal scanning service
Docker – Official image coming soon
Planned command: docker run cyberdudebivash/op-model-sentry --dir /models

Support SLA: 1 year included with license purchase.