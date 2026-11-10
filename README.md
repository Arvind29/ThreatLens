# ThreatLens by LensLabs

Multi-source threat intelligence search, simplified.

## Current release
- Responsive investigation interface for IP addresses, domains, URLs and file hashes.
- Server-side live lookup adapters for ThreatFox and URLhaus.
- Provider-native records, timestamps and statuses; no fabricated detections, scores or clean verdicts.
- VirusTotal, AbuseIPDB, AlienVault OTX and GreyNoise remain planned integrations.
- Public preview; no login.

## Configure threat-intelligence access
Set the following server-side environment variable in Vercel (Production and Preview as needed):

`ABUSECH_AUTH_KEY` — API key from abuse.ch, used by ThreatFox and URLhaus.

Do not add this key to client-side code, commit it to Git, or share it in chat. After adding or changing the variable, redeploy the project.

## Run locally
```bash
npm install
npm run dev
```

Create a local `.env.local` file containing `ABUSECH_AUTH_KEY=your_key`. Keep this file out of Git.

## Provider coverage
- ThreatFox: exact IOC search.
- URLhaus: URL, host (domain/IP), and SHA-256 payload lookups.
- Other four providers are listed in the UI but are not queried yet.

A provider match is evidence from that source, not a definitive verdict. No match does not mean safe. Provider coverage, rate limits and licensing terms apply. Review each provider's current terms before commercial use.


## Technology stack and architecture

### Languages and frameworks
- **TypeScript** — IOC normalization, provider adapters and application logic.
- **Next.js 14 (App Router)** — web application and server-side API routes.
- **React 18** — investigation interface and client-side state.
- **HTML / JSX and CSS** — page structure and styling.

### Runtime libraries
| Library | Purpose |
|---|---|
| `next` | Application framework, routing and server-side API execution |
| `react` / `react-dom` | UI rendering and components |
| `lucide-react` | Interface icons |

### Threat-intelligence integrations
| Provider | Current implementation |
|---|---|
| ThreatFox (abuse.ch) | Live exact-IOC lookup |
| URLhaus (abuse.ch) | Live URL, host/domain/IP and SHA-256 payload lookup |
| VirusTotal | Planned; not queried in the current release |
| AbuseIPDB | Planned; not queried in the current release |
| AlienVault OTX | Planned; not queried in the current release |
| GreyNoise | Planned; not queried in the current release |

ThreatFox and URLhaus use the server-side `ABUSECH_AUTH_KEY` environment variable. Keep it out of client-side bundles and Git history.

### Development and deployment
- **Node.js / npm** — development runtime and dependency management.
- **TypeScript** — static type checking.
- **Vercel** — application hosting and deployment.

### Investigation flow
1. The analyst submits an IP address, domain, URL or file hash.
2. The Next.js server routes the indicator to the supported provider adapters.
3. ThreatFox and URLhaus return provider-native records and statuses.
4. The interface presents source attribution and returned evidence without inventing a universal reputation score.

**Important:** a provider match is evidence from that provider, not a definitive verdict. No match does not mean safe. Provider limits and terms apply. No database or user login is required in the current public preview.
