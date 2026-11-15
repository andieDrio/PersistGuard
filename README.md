# PersistGuard

Centralized, cross-platform persistence detection and threat hunting platform (early scaffold).

## Architecture
- Web dashboard: planned Next.js + TypeScript
- Backend: planned FastAPI + PostgreSQL
- Endpoint agents: planned Go, outbound-only mTLS, read-only collectors
- Detection: initial explainable heuristic scoring implemented in `backend/persistguard/detection.py`

## Run current tests
```bash
cd backend
python -m unittest discover -s tests -v
```

**Status:** Initial detection scoring module only. No live scanning, authentication, agent enrollment, or dashboard yet. Do not use for production security decisions.
