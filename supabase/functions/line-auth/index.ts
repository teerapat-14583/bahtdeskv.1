// Baht Desk: sign in with LINE (LIFF).
// The page sends the LIFF ID token. We ask LINE to verify it (so it cannot be faked), then sign the person in to Supabase.
// First visit: a customer account is created and set to Observe automatically.
// Staff and admin are recognised by the role an admin gave their LINE account (app_metadata.role).
import { createClient } from "npm:@supabase/supabase-js@2";

const CHANNEL_ID = Deno.env.get("LINE_CHANNEL_ID") ?? "2012661425"; // LINE Login channel "Baht Desk"
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });

// a stable password per LINE user, known only to this function (derived from the project's secret key)
async function derive(secret: string, msg: string) {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(msg));
  return Array.from(new Uint8Array(sig)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const { idToken } = await req.json();
    if (!idToken) return json({ error: "idToken required" }, 400);

    // 1. LINE checks the token was issued by LINE for our channel and has not expired
    const v = await fetch("https://api.line.me/oauth2/v2.1/verify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ id_token: idToken, client_id: CHANNEL_ID }),
    });
    const p = await v.json();
    if (!v.ok || !p.sub) return json({ error: "LINE verification failed: " + (p.error_description || p.error || v.status) }, 401);

    const url = Deno.env.get("SUPABASE_URL")!;
    const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
    const admin = createClient(url, service, { auth: { persistSession: false } });
    const pub = createClient(url, anon, { auth: { persistSession: false } });

    // 2. one Supabase account per LINE user
    const email = `line_${String(p.sub).toLowerCase()}@clients.bahtdesk.app`;
    const password = await derive(service, "line:" + p.sub);
    let s = await pub.auth.signInWithPassword({ email, password });
    if (s.error) {
      const c = await admin.auth.admin.createUser({
        email, password, email_confirm: true,
        user_metadata: { name: p.name || "", picture: p.picture || "", line_sub: p.sub, via: "line" },
        app_metadata: { role: "client" },
      });
      if (c.error) throw c.error;
      s = await pub.auth.signInWithPassword({ email, password });
      if (s.error) throw s.error;
    }
    const u = s.data.user!;
    const uid = u.id;
    const role = (u.app_metadata && u.app_metadata.role) || "client";
    if ((u.user_metadata?.name || "") !== (p.name || "") || (u.user_metadata?.picture || "") !== (p.picture || "")) {
      await admin.auth.admin.updateUserById(uid, { user_metadata: { ...u.user_metadata, name: p.name || "", picture: p.picture || "" } });
    }

    // 3. customers: an Observe account on the first visit
    if (role === "client") {
      const id = "KYC-" + uid;
      const { data: ex } = await admin.from("bd_kyc_req").select("id").eq("id", id).maybeSingle();
      if (!ex) {
        const now = Date.now();
        await admin.from("bd_kyc_req").insert({
          id,
          data: { id, uid, src: "line", lineSub: p.sub, lineName: p.name || "", picture: p.picture || "", name: p.name || "LINE user",
            first: "", last: "", username: "", phone: "", line: "", st: "observe", want: "observe", ts: now, upd: now },
        });
      }
    }

    return json({
      access_token: s.data.session!.access_token,
      refresh_token: s.data.session!.refresh_token,
      expires_in: s.data.session!.expires_in,
      user: { id: uid, role, name: p.name || "", picture: p.picture || "" },
    });
  } catch (e) {
    return json({ error: String((e as Error)?.message || e) }, 400);
  }
});
