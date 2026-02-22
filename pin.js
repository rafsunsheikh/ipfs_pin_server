const express = require("express");
const multer = require("multer");
const FormData = require("form-data");
const fetch = require("node-fetch");
const cors = require("cors");
const fs = require("fs");
require("dotenv").config();

const upload = multer();
const app = express();
app.use(
  cors({
    origin: "*",
    allowedHeaders: ["Authorization", "Content-Type"],
    methods: ["GET", "POST", "OPTIONS"],
  })
);
app.use(express.json());

const PINATA_FILE_ENDPOINT = "https://api.pinata.cloud/pinning/pinFileToIPFS";
const PINATA_JSON_ENDPOINT = "https://api.pinata.cloud/pinning/pinJSONToIPFS";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const allowedRoles = [
  "Pooling agents",
  "Presiding officer",
  "Returning officer",
  "District Commission Office",
  "District Election Commission Office",
  "Election Commission HQ",
];

function getAuthHeader() {
  if (process.env.PINATA_JWT) return { Authorization: `Bearer ${process.env.PINATA_JWT}` };
  if (process.env.PINATA_API_KEY && process.env.PINATA_API_SECRET) {
    return {
      pinata_api_key: process.env.PINATA_API_KEY,
      pinata_secret_api_key: process.env.PINATA_API_SECRET,
    };
  }
  throw new Error("Pinata credentials missing (set PINATA_JWT or API key/secret)");
}

// --- Supabase admin helper (dynamic import keeps CJS file working) ---
let supabaseAdmin = null;
async function getSupabaseAdmin() {
  if (supabaseAdmin) return supabaseAdmin;
  const { createClient } = await import("@supabase/supabase-js");
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing");
  }
  supabaseAdmin = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
  return supabaseAdmin;
}

async function requireAdmin(req, res) {
  try {
    const token = (req.headers.authorization || "").replace(/Bearer\s+/i, "").trim();
    if (!token) return res.status(401).json({ error: "Missing bearer token" });
    const adminClient = await getSupabaseAdmin();
    const { data, error } = await adminClient.auth.getUser(token);
    if (error || !data?.user) return res.status(401).json({ error: "Invalid token" });
    if (!ADMIN_EMAIL || data.user.email.toLowerCase() !== ADMIN_EMAIL.toLowerCase()) {
      return res.status(403).json({ error: "Forbidden" });
    }
    return data.user;
  } catch (err) {
    return res.status(500).json({ error: err.message || "admin check failed" });
  }
}

// list pending (approved !== true) users
app.get("/api/admin/pending-users", async (req, res) => {
  const me = await requireAdmin(req, res);
  if (!me || me.error) return;
  try {
    const adminClient = await getSupabaseAdmin();
    const pending = [];
    let page = 1;
    const perPage = 100;
    while (true) {
      const { data, error } = await adminClient.auth.admin.listUsers({ page, perPage });
      if (error) throw error;
      if (!data?.users?.length) break;
      for (const u of data.users) {
        const meta = u.user_metadata || {};
        if (meta.approved === true) continue;
        if (!allowedRoles.includes(meta.category)) continue;
        pending.push({
          id: u.id,
          email: u.email,
          category: meta.category,
          fullName: meta.fullName,
          phone: meta.phone,
          organization: meta.organization,
          division: meta.division,
          district: meta.district,
          constituency: meta.constituency,
          booth: meta.booth,
          created_at: u.created_at,
        });
      }
      if (data.users.length < perPage) break;
      page += 1;
    }
    return res.json({ pending });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to list users" });
  }
});

// list all users with optional filters/search (admin only)
app.get("/api/admin/users", async (req, res) => {
  const me = await requireAdmin(req, res);
  if (!me || me.error) return;
  const { q, division, district, constituency } = req.query;
  try {
    const adminClient = await getSupabaseAdmin();
    const results = [];
    let page = 1;
    const perPage = 100;
    while (true) {
      const { data, error } = await adminClient.auth.admin.listUsers({ page, perPage });
      if (error) throw error;
      if (!data?.users?.length) break;
      for (const u of data.users) {
        const meta = u.user_metadata || {};
        const locMatch =
          (!division || meta.division === division) &&
          (!district || meta.district === district) &&
          (!constituency || meta.constituency === constituency);
        const term = (q || "").toLowerCase();
        const text = `${u.email || ""} ${meta.fullName || ""} ${meta.category || ""}`.toLowerCase();
        const searchMatch = !term || text.includes(term);
        if (locMatch && searchMatch) {
          results.push({
            id: u.id,
            email: u.email,
            category: meta.category,
            fullName: meta.fullName,
            phone: meta.phone,
            organization: meta.organization,
            division: meta.division,
            district: meta.district,
            constituency: meta.constituency,
            booth: meta.booth,
            approved: meta.approved,
            created_at: u.created_at,
          });
        }
      }
      if (data.users.length < perPage) break;
      page += 1;
    }
    return res.json({ users: results });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to list users" });
  }
});

// generic user auth (non-admin) for scoped directory search
async function requireUser(req, res) {
  try {
    const token = (req.headers.authorization || "").replace(/Bearer\s+/i, "").trim();
    if (!token) return res.status(401).json({ error: "Missing bearer token" });
    const adminClient = await getSupabaseAdmin();
    const { data, error } = await adminClient.auth.getUser(token);
    if (error || !data?.user) return res.status(401).json({ error: "Invalid token" });
    return data.user;
  } catch (err) {
    return res.status(500).json({ error: err.message || "user check failed" });
  }
}

app.get("/api/search/users", async (req, res) => {
  const user = await requireUser(req, res);
  if (!user || user.error) return;
  const meta = user.user_metadata || {};
  const role = meta.category;
  const { q } = req.query;
  let scope = {};
  if (role === "District Commission Office" || role === "District Election Commission Office") {
    scope = { district: meta.district };
  } else if (role === "Returning officer") {
    scope = { district: meta.district, constituency: meta.constituency };
  } else {
    scope = { email: user.email }; // minimal access
  }
  try {
    const adminClient = await getSupabaseAdmin();
    const results = [];
    let page = 1;
    const perPage = 100;
    while (true) {
      const { data, error } = await adminClient.auth.admin.listUsers({ page, perPage });
      if (error) throw error;
      if (!data?.users?.length) break;
      for (const u of data.users) {
        const m = u.user_metadata || {};
        const inScope =
          (scope.email && u.email === scope.email) ||
          ((!scope.email && scope.district === m.district) &&
            (!scope.constituency || scope.constituency === m.constituency));
        if (!inScope) continue;
        const term = (q || "").toLowerCase();
        const text = `${u.email || ""} ${m.fullName || ""} ${m.category || ""}`.toLowerCase();
        if (term && !text.includes(term)) continue;
        results.push({
          id: u.id,
          email: u.email,
          category: m.category,
          fullName: m.fullName,
          phone: m.phone,
          organization: m.organization,
          division: m.division,
          district: m.district,
          constituency: m.constituency,
          booth: m.booth,
          approved: m.approved,
          created_at: u.created_at,
        });
      }
      if (data.users.length < perPage) break;
      page += 1;
    }
    return res.json({ users: results });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to list users" });
  }
});

// approve / reject user
app.post("/api/admin/approve", async (req, res) => {
  const me = await requireAdmin(req, res);
  if (!me || me.error) return;
  const { userId, approve } = req.body || {};
  if (!userId || typeof approve !== "boolean") return res.status(400).json({ error: "userId and approve required" });
  try {
    const adminClient = await getSupabaseAdmin();
    if (approve) {
      const { data, error } = await adminClient.auth.admin.updateUserById(userId, {
        user_metadata: { approved: true },
      });
      if (error) throw error;
      return res.json({ ok: true, user: data.user });
    } else {
      const { error } = await adminClient.auth.admin.deleteUser(userId);
      if (error) throw error;
      return res.json({ ok: true, deleted: userId });
    }
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to update user" });
  }
});

app.post("/api/pin", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "file is required" });
    const form = new FormData();
    form.append("file", req.file.buffer, req.file.originalname);

    const headers = { ...getAuthHeader(), ...form.getHeaders() };

    const r = await fetch(PINATA_FILE_ENDPOINT, { method: "POST", headers, body: form });
    if (!r.ok) {
      const text = await r.text();
      return res.status(500).json({ error: text });
    }
    const data = await r.json();
    return res.json({ cid: data.IpfsHash, size: data.PinSize, timestamp: data.Timestamp });
  } catch (err) {
    return res.status(500).json({ error: err.message || "pin failed" });
  }
});

app.post("/api/pin-json", express.json(), async (req, res) => {
  try {
    const headers = { ...getAuthHeader(), "Content-Type": "application/json" };
    const r = await fetch(PINATA_JSON_ENDPOINT, {
      method: "POST",
      headers,
      body: JSON.stringify(req.body),
    });
    if (!r.ok) {
      const text = await r.text();
      return res.status(500).json({ error: text });
    }
    const data = await r.json();
    return res.json({ cid: data.IpfsHash });
  } catch (err) {
    return res.status(500).json({ error: err.message || "pin failed" });
  }
});

const port = process.env.PORT || process.env.PIN_SERVER_PORT || 3001;
app.listen(port, () => {
  console.log(`Pin server listening on http://localhost:${port}`);
});
