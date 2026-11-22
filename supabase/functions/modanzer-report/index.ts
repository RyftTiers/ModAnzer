// ModAnzer screenshare reports -> the RyftTiers Supabase database.
// The app sends {report}. This checks it, trims it and saves it to the
// `modanzer_reports` table under a short reference code, which it sends back
// for the player to give to staff. Staff run /ssresult with that code in the
// RyftTiers Discord bot to see the report.
// Deploy it in the RyftTiers Supabase project with JWT verification off (the
// script sends no Supabase key). It uses the SUPABASE_URL and
// SUPABASE_SERVICE_ROLE_KEY that Supabase gives every function, so there are no
// secrets to set. The table is in supabase/modanzer_reports.sql.

import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.45.0";

const MAX_BODY = 1_000_000;
const LIMIT_PER_MINUTE = 6;
const recent = new Map<string, { n: number; t: number }>();
let client: SupabaseClient | null = null;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const str = (v: unknown, max: number) => (typeof v === "string" ? v.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "").slice(0, max) : "");
const num = (v: unknown) => (typeof v === "number" && Number.isFinite(v) ? Math.max(0, Math.min(1_000_000, Math.floor(v))) : 0);
const arr = (v: unknown, max: number): unknown[] => (Array.isArray(v) ? v.slice(0, max) : []);
const obj = (v: unknown): Record<string, unknown> | null => (v && typeof v === "object" && !Array.isArray(v) ? v as Record<string, unknown> : null);

function alerts(v: unknown) {
  return arr(v, 500).map((a) => {
    const o = obj(a) ?? {};
    return { Time: str(o.Time, 10), Level: o.Level === "Red" ? "Red" : "Yellow", Text: str(o.Text, 400) };
  });
}

// Keep only the fields ModAnzer sends, with sane sizes.
export function sanitize(raw: unknown) {
  const r = obj(raw);
  if (!r) return null;
  const m = obj(r.mods), s = obj(r.system), i = obj(r.injection);
  return {
    tool: "ModAnzer",
    mode: str(r.mode, 40),
    finished: str(r.finished, 40),
    // Only older ModAnzer versions send this; new ones use the reference code instead.
    discordId: typeof r.discordId === "string" && /^\d{17,20}$/.test(r.discordId) ? r.discordId : "",
    accounts: arr(r.accounts, 20).map((a) => str(a, 16)).filter(Boolean),
    mods: m && {
      Folders: arr(m.Folders, 50).map((f) => str(f, 120)),
      Verified: num(m.Verified), CurseForgeApp: num(m.CurseForgeApp), Unknown: num(m.Unknown), Cheat: num(m.Cheat),
      Cheats: arr(m.Cheats, 300).map((c) => { const o = obj(c) ?? {}; return { Name: str(o.Name, 120), Where: str(o.Where, 120), Strings: str(o.Strings, 200) }; }),
      Unknowns: arr(m.Unknowns, 500).map((u) => { const o = obj(u) ?? {}; return { Name: str(o.Name, 120), Where: str(o.Where, 120) }; }),
      // Every mod that was scanned, with its result.
      All: arr(m.All, 3000).map((x) => {
        const o = obj(x) ?? {};
        const st = typeof o.Status === "string" && ["OK", "CF", "UNKNOWN", "CHECK", "CHEAT"].includes(o.Status) ? o.Status : "UNKNOWN";
        return { Status: st, Name: str(o.Name, 120), Title: str(o.Title, 200), Where: str(o.Where, 120) };
      }),
    },
    system: s && { Admin: s.Admin === true, Alerts: alerts(s.Alerts) },
    injection: i && { Admin: i.Admin === true, Uptime: str(i.Uptime, 30), GameFolder: str(i.GameFolder, 160), Alerts: alerts(i.Alerts) },
  };
}

// 6 characters from 31 letters and digits (no 0/o, 1/l/i), about 887 million codes.
const CODE_CHARS = "23456789abcdefghjkmnpqrstuvwxyz";
function newCode(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  // 248 is the largest multiple of 31 below 256; redraw bytes above it so every character is equally likely.
  return Array.from(bytes, (b) => {
    while (b >= 248) b = crypto.getRandomValues(new Uint8Array(1))[0];
    return CODE_CHARS[b % 31];
  }).join("");
}

async function shortHash(text: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  const url = Deno.env.get("SUPABASE_URL");
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !key) return json({ error: "reports are not set up on the server yet" }, 503);

  const ip = (req.headers.get("x-forwarded-for") ?? "?").split(",")[0].trim();
  const now = Date.now();
  const r0 = recent.get(ip);
  if (r0 && now - r0.t < 60_000) {
    if (++r0.n > LIMIT_PER_MINUTE) return json({ error: "too many reports, try again in a minute" }, 429);
  } else {
    if (recent.size > 5000) recent.clear();
    recent.set(ip, { n: 1, t: now });
  }

  const raw = await req.text();
  if (raw.length > MAX_BODY) return json({ error: "report too large" }, 413);
  let body: { report?: unknown };
  try {
    body = JSON.parse(raw);
  } catch {
    return json({ error: "body must be JSON" }, 400);
  }
  const report = sanitize(body.report);
  if (!report || (!report.mods && !report.system && !report.injection)) return json({ error: "missing report" }, 400);

  try {
    client ??= createClient(url, key, { auth: { persistSession: false } });
    const senderHash = await shortHash(ip + key); // groups reports from one sender without storing the IP
    // ref_code is unique; on the rare clash, draw a new code.
    for (let attempt = 0; attempt < 5; attempt++) {
      const refCode = newCode();
      const { error } = await client.from("modanzer_reports").insert({
        ref_code: refCode,
        tool: report.tool,
        mode: report.mode,
        finished: report.finished,
        discord_id: report.discordId || null,
        accounts: report.accounts,
        mods: report.mods,
        system: report.system,
        injection: report.injection,
        sender_hash: senderHash,
      });
      if (!error) return json({ ok: true, code: refCode });
      if (error.code !== "23505") throw new Error(error.message);
    }
    return json({ error: "the report server could not make a code - try again" }, 502);
  } catch (err) {
    console.error("insert failed:", err instanceof Error ? err.message : err);
    return json({ error: "the report server could not save it - try again" }, 502);
  }
});
