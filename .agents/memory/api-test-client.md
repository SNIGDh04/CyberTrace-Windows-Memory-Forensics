---
name: API test client availability
description: A runtime dependency constraint for testing FastAPI routes.
---

Starlette's `TestClient` fails to import unless `httpx2` is installed in this workspace.

**Why:** The installed Starlette version explicitly checks for `httpx2`, so route tests should not assume the conventional test client is available.

**How to apply:** Check the test client before adding API tests. Prefer direct route-function tests with an isolated database unless adding `httpx2` is justified.