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
