# Test Evidence

Date: 2026-05-04

## Local Gates

- `npm run verify`: passed.
- `npm run e2e`: passed, 2 Playwright smoke tests.
- `npm audit --omit=dev`: passed, 0 vulnerabilities.
- Production build: passed.

## Runtime GLM/API Checks

- Z.ai key stored in Keychain under `codex-zai-api-key`.
- General Z.ai endpoint returned insufficient-balance response.
- Coding endpoint succeeded with `glm-5.1`.
- `/api/health`: returned `mode: live-glm`.
- `/api/jira/issue`: returned valid Jira-shaped GLM output using `glm-5-turbo`.
- `/api/okta/user-risk`: returned valid Okta-shaped GLM output.
- `/api/agent-run`: reached HITL approval in 53.4 seconds with no errors.
- `/api/resume-run`: completed final report in 51.5 seconds with no errors.
- `/api/replay-run`: forked a checkpoint in 6.7 seconds with no errors.

## Screenshot Evidence

- Desktop: `docs/screenshot-desktop.png`
- Mobile: `docs/screenshot-mobile.png`
