# ThreatLens by LensLabs

Multi-source threat intelligence search, simplified.

## Current release
- Responsive investigation interface for IP addresses, domains, URLs and file hashes.
- Provider directory: VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, ThreatFox and GreyNoise.
- Honest source states: all providers are currently **Not configured**. Searches are not sent to external providers.
- No fabricated detections, risk scores or clean verdicts.
- Public preview; no login.

## Run locally
```bash
npm install
npm run dev
```

## Next milestone
Implement server-side provider adapters one at a time. Keep provider-native verdicts and timestamps. Use explicit states such as not queried, not configured, API error and rate limited. Never interpret missing data as benign.

Do not expose API keys in client-side code. Review each provider's current API terms and commercial licensing before product use. Absence of detections does not establish that an indicator is safe.
