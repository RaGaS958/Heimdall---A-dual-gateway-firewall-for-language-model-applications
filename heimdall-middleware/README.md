---
title: Heimdall Middleware
sdk: docker
app_port: 7860
---

# Heimdall middleware

FastAPI service holding both gateways. See `../knowledge-base/01-architecture` and `../knowledge-base/06-operations/operations.md`.

Deploying needs `HEIMDALL_ENV=production` with `ADMIN_KEY`, `INTERNAL_AUTH_KEY` and `SESSION_SIGNING_KEY`, each at least 24 characters. The service refuses to start without them.
