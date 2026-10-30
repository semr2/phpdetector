# Demo fixture showcase

The demo showcase reads static JSON fixtures from `fixtures/demo/`. It does not call the live scanner, make outbound requests, or write to Prisma.

To enable it for local development, add this server-side setting to the existing `.env` file and restart the dev server:

```dotenv
DEMO_MODE=true
```

Then open `/demo`. The ordinary `/` dashboard and its live scan API remain separate. Demo fixtures are disabled whenever `NODE_ENV=production`, even if `DEMO_MODE=true` is accidentally set. Do not use a `NEXT_PUBLIC_` prefix for this setting.

Fixture data is labeled simulated throughout the page and generated reports. Demo findings are restricted to `potential` or `inconclusive`; the fixture schema rejects `confirmed` findings.
