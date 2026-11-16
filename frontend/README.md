# SecureMCP operator console

Use `npm ci`, `npm run dev`, and open [localhost:5173](http://localhost:5173) with the native gateway and Keycloak running. The Vite proxy defaults to gateway port 8000 and accepts `GATEWAY_PROXY` for development.

Run `npm run lint` and `npm run build` to verify the frontend. Install Chromium with `npx playwright install chromium` and run `npm run test:e2e` with the generated `DEMO_PASSWORD` exported. Set `SMCP_SCREENSHOT_DIR` to capture the authenticated Overview and Attack Lab screenshots. The tests use the seeded Keycloak realm and real APIs.
