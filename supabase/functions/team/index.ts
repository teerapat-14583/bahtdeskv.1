// Baht Desk: team management (admin only).
// action "list": everyone who has entered through LINE, with their role.
// action "set":  give a person the role client, staff or admin.
import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
    // who is asking? must be signed in with role admin
    const token = (req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    const me = await admin.auth.getUser(token);
    if (me.error || !me.data.user) return json({ error: "Please sign in again" }, 401);
    if (me.data.user.app_metadata?.role !== "admin") return json({ error: "Only an admin can manage the team" }, 403);

    const body = await req.json();
    if (body.action === "list") {
      const out: unknown[] = [];
      for (let page = 1; page <= 20; page++) {
        const r = await admin.auth.admin.listUsers({ page, perPage: 200 });
        if (r.error) throw r.error;
        for (const u of r.data.users) {
          const m = u.user_metadata || {};
          out.push({ id: u.id, role: u.app_metadata?.role || "client", name: m.name || m.username || "", picture: m.picture || "",
            via: m.via || (u.email && u.email.endsWith("@clients.bahtdesk.app") ? "username" : "email"),
            email: u.email && !u.email.endsWith("@clients.bahtdesk.app") ? u.email : "", last: u.last_sign_in_at, created: u.created_at });
        }
        if (r.data.users.length < 200) break;
      }
      return json({ users: out });
    }
    if (body.action === "set") {
      const role = String(body.role || "");
      if (!["client", "staff", "admin"].includes(role)) return json({ error: "Unknown role" }, 400);
      if (body.uid === me.data.user.id && role !== "admin") return json({ error: "You cannot remove your own admin role" }, 400);
      const t = await admin.auth.admin.getUserById(body.uid);
      if (t.error || !t.data.user) return json({ error: "Person not found" }, 404);
      const r = await admin.auth.admin.updateUserById(body.uid, { app_metadata: { ...t.data.user.app_metadata, role } });
      if (r.error) throw r.error;
      return json({ ok: true, id: body.uid, role });
    }
    return json({ error: "Unknown action" }, 400);
  } catch (e) {
    return json({ error: String((e as Error)?.message || e) }, 400);
  }
});
