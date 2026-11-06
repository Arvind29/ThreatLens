import { NextRequest, NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Kind = "IP address" | "Domain" | "URL" | "File hash";

function validate(value: string, kind: Kind) {
  if (kind === "IP address") {
    if (value.includes(":")) return /^[0-9a-f:]+$/i.test(value) && value.includes(":");
    if (!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return false;
    return value.split(".").every((part) => Number(part) >= 0 && Number(part) <= 255);
  }
  if (kind === "Domain") return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(value);
  if (kind === "URL") {
    try { return ["http:", "https:"].includes(new URL(value).protocol); } catch { return false; }
  }
  return /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(value);
}

async function queryThreatFox(value: string, key: string) {
  const response = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Auth-Key": key },
    body: JSON.stringify({ query: "search_ioc", search_term: value, exact_match: true }),
    cache: "no-store",
    signal: AbortSignal.timeout(12000)
  });
  if (!response.ok) throw new Error(`ThreatFox HTTP ${response.status}`);
  const json = await response.json();
  if (json.query_status === "no_result") return { status: "No match", count: 0, records: [] };
  if (json.query_status !== "ok") throw new Error(json.query_status || "ThreatFox query failed");
  const records = Array.isArray(json.data) ? json.data : [];
  return { status: records.length ? "Match found" : "No match", count: records.length, reportUrl: "https://threatfox.abuse.ch/browse.php?search=" + encodeURIComponent(value), records: records.slice(0, 10).map((x: any) => ({
    indicator: x.ioc, type: x.ioc_type, threat: x.threat_type_desc || x.threat_type,
    malware: x.malware_printable || x.malware || null, confidence: x.confidence_level ?? null,
    firstSeen: x.first_seen || null, lastSeen: x.last_seen || null, tags: x.tags || []
  })) };
}

async function queryUrlhaus(value: string, kind: Kind, key: string) {
  let endpoint = "https://urlhaus-api.abuse.ch/v1/url/";
  let form: URLSearchParams;
  if (kind === "URL") form = new URLSearchParams({ url: value });
  else if (kind === "Domain" || kind === "IP address") {
    endpoint = "https://urlhaus-api.abuse.ch/v1/host/";
    form = new URLSearchParams({ host: value });
  } else {
    endpoint = "https://urlhaus-api.abuse.ch/v1/payload/";
    form = new URLSearchParams({ sha256_hash: value });
  }
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Auth-Key": key },
    body: form.toString(),
    cache: "no-store",
    signal: AbortSignal.timeout(12000)
  });
  if (!response.ok) throw new Error(`URLhaus HTTP ${response.status}`);
  const json = await response.json();
  if (json.query_status === "no_results" || json.query_status === "no_result") return { status: "No match", count: 0, records: [] };
  if (json.query_status !== "ok") throw new Error(json.query_status || "URLhaus query failed");
  const list = json.urls || json.payloads || (json.url ? [json] : []);
  const records = (Array.isArray(list) ? list : []).slice(0, 10).map((x: any) => ({
    indicator: x.url || x.host || x.sha256_hash || value,
    status: x.url_status || x.file_type || null,
    threat: x.threat || x.signature || null,
    firstSeen: x.date_added || x.firstseen || null,
    lastSeen: x.last_online || null,
    tags: x.tags || []
  }));
  return { status: records.length ? "Match found" : "No match", count: records.length, records, reportUrl: "https://urlhaus.abuse.ch/browse.php?search=" + encodeURIComponent(value) };
}


async function queryVirusTotal(value: string, kind: Kind, key: string) {
  let resource: string;
  if (kind === "IP address") resource = `ip_addresses/${encodeURIComponent(value)}`;
  else if (kind === "Domain") resource = `domains/${encodeURIComponent(value)}`;
  else if (kind === "URL") {
    const encoded = Buffer.from(value, "utf8").toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    resource = `urls/${encoded}`;
  } else resource = `files/${encodeURIComponent(value)}`;

  const response = await fetch(`https://www.virustotal.com/api/v3/${resource}`, {
    headers: { "x-apikey": key, "Accept": "application/json" },
    cache: "no-store",
    signal: AbortSignal.timeout(15000)
  });
  if (response.status === 404) return { status: "No match", count: 0, records: [], detail: "VirusTotal has no report for this indicator." };
  if (response.status === 401 || response.status === 403) throw new Error(`VirusTotal authentication or permission error (HTTP ${response.status}). Check the API key and plan permissions.`);
  if (response.status === 429) throw new Error("VirusTotal rate limit reached. Try again later.");
  if (!response.ok) throw new Error(`VirusTotal HTTP ${response.status}`);

  const json = await response.json();
  const attr = json?.data?.attributes || {};
  const stats = attr.last_analysis_stats || {};
  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  const total = Object.values(stats).reduce((sum: number, n: any) => sum + Number(n || 0), 0);
  const names = Array.isArray(attr.names) ? attr.names.slice(0, 5) : [];
  const record = {
    indicator: value,
    threat: malicious > 0 ? "Malicious detections reported" : suspicious > 0 ? "Suspicious detections reported" : "Analysis report available",
    status: attr.reputation !== undefined ? `Community reputation: ${attr.reputation}` : null,
    malicious, suspicious, harmless: Number(stats.harmless || 0), undetected: Number(stats.undetected || 0), reputation: attr.reputation ?? null,
    totalEngines: total, firstSeen: attr.first_submission_date ? new Date(attr.first_submission_date * 1000).toISOString() : null,
    lastSeen: attr.last_analysis_date ? new Date(attr.last_analysis_date * 1000).toISOString() : null,
    tags: [...(Array.isArray(attr.tags) ? attr.tags.slice(0, 8) : []), ...names]
  };
  const reportType = kind === "IP address" ? "ip-address" : kind === "Domain" ? "domain" : kind === "URL" ? "url" : "file";
  const reportId = kind === "URL" ? Buffer.from(value, "utf8").toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_") : encodeURIComponent(value);
  return { status: "Match found", count: 1, records: [record], reportUrl: "https://www.virustotal.com/gui/" + reportType + "/" + reportId };
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const value = String(body?.value || "").trim();
    const kind = body?.kind as Kind;
    if (!value || !["IP address", "Domain", "URL", "File hash"].includes(kind) || !validate(value, kind)) {
      return NextResponse.json({ error: "Invalid indicator or indicator type." }, { status: 400 });
    }
    const abuseKey = process.env.ABUSECH_AUTH_KEY;
    const vtKey = process.env.VIRUSTOTAL_API_KEY;
    if (!abuseKey && !vtKey) {
      return NextResponse.json({
        indicator: value,
        providers: [
          { name: "VirusTotal", status: "Not configured", detail: "Add VIRUSTOTAL_API_KEY in Vercel environment variables." },
          { name: "ThreatFox", status: "Not configured", detail: "Add ABUSECH_AUTH_KEY in Vercel environment variables." },
          { name: "URLhaus", status: "Not configured", detail: "Add ABUSECH_AUTH_KEY in Vercel environment variables." }
        ],
        note: "No external query was made. No verdict has been inferred."
      });
    }
    const tasks = [
      { name: "VirusTotal", key: vtKey, run: () => queryVirusTotal(value, kind, vtKey!) },
      { name: "ThreatFox", key: abuseKey, run: () => queryThreatFox(value, abuseKey!) },
      { name: "URLhaus", key: abuseKey, run: () => queryUrlhaus(value, kind, abuseKey!) }
    ];
    const settled = await Promise.all(tasks.map(async (task) => {
      if (!task.key) return { name: task.name, status: "Not configured", detail: task.name === "VirusTotal" ? "Add VIRUSTOTAL_API_KEY in Vercel environment variables." : "Add ABUSECH_AUTH_KEY in Vercel environment variables." };
      try { return { name: task.name, ...await task.run() }; }
      catch (error) { return { name: task.name, status: "API error", detail: error instanceof Error ? error.message : "Provider request failed." }; }
    }));
    const providers = settled;
    return NextResponse.json({ indicator: value, queriedAt: new Date().toISOString(), providers, note: "A provider match is evidence from that source, not a definitive verdict. No match does not mean safe." });
  } catch {
    return NextResponse.json({ error: "Unable to process the lookup." }, { status: 500 });
  }
}
