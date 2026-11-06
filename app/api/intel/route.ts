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
  return { status: records.length ? "Match found" : "No match", count: records.length, records: records.slice(0, 10).map((x: any) => ({
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
  return { status: records.length ? "Match found" : "No match", count: records.length, records };
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const value = String(body?.value || "").trim();
    const kind = body?.kind as Kind;
    if (!value || !["IP address", "Domain", "URL", "File hash"].includes(kind) || !validate(value, kind)) {
      return NextResponse.json({ error: "Invalid indicator or indicator type." }, { status: 400 });
    }
    const key = process.env.ABUSECH_AUTH_KEY;
    if (!key) {
      return NextResponse.json({
        indicator: value,
        providers: [
          { name: "ThreatFox", status: "Not configured", detail: "Add ABUSECH_AUTH_KEY in Vercel environment variables." },
          { name: "URLhaus", status: "Not configured", detail: "Add ABUSECH_AUTH_KEY in Vercel environment variables." }
        ],
        note: "No external query was made. No verdict has been inferred."
      });
    }
    const settled = await Promise.allSettled([
      queryThreatFox(value, key),
      queryUrlhaus(value, kind, key)
    ]);
    const providers = ["ThreatFox", "URLhaus"].map((name, i) => {
      const item = settled[i];
      if (item.status === "rejected") return { name, status: "API error", detail: item.reason instanceof Error ? item.reason.message : "Provider request failed." };
      return { name, ...item.value };
    });
    return NextResponse.json({ indicator: value, queriedAt: new Date().toISOString(), providers, note: "A provider match is evidence from that source, not a definitive verdict. No match does not mean safe." });
  } catch {
    return NextResponse.json({ error: "Unable to process the lookup." }, { status: 500 });
  }
}
