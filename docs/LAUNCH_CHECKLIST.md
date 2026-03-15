# PacketQL Launch Checklist (Public Repo)

Use this checklist before announcing PacketQL as production-ready.

## Stage 1 - Public Beta (can publish now)

- [x] Add root `README.md` with clear install/run instructions
- [x] Add open-source `LICENSE`
- [x] Add `.env.example`
- [x] Label status as **Public Beta**
- [x] Add architecture diagram and supporting architecture doc
- [ ] Add UI screenshots
- [ ] Add sample PCAP + expected output walkthrough

## Stage 2 - Reliability Baseline

- [ ] CI pipeline: frontend build + backend tests + Go tests
- [ ] Pin dependency strategy and update policy
- [ ] Add health checks for API/frontend/enrich
- [ ] Add backup/recovery notes for runtime data

## Stage 3 - Security Hardening

- [ ] Move Django `SECRET_KEY` to env
- [ ] Set `DEBUG=False` for production
- [ ] Restrict `ALLOWED_HOSTS` and CORS origins
- [ ] Review unauthenticated endpoints and enforce auth where needed
- [ ] Add `SECURITY.md` and vulnerability disclosure process

## Stage 4 - Production Claim Gate

Only claim "production-ready" when all are true:

- [ ] Clean install verified on fresh host
- [ ] Runbook for upgrades/rollback exists
- [ ] Monitoring and alerting are active
- [ ] Security review complete
- [ ] Known limits documented (file size, throughput, supported protocols)

## Suggested GitHub Release Labels

- `v0.x` = Public Beta
- `v1.0` = Production Ready (after Stage 4)
