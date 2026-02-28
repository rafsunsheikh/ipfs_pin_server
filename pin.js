const express = require("express");
const multer = require("multer");
const FormData = require("form-data");
const fetch = require("node-fetch");
const cors = require("cors");
const fs = require("fs");
const { Interface } = require("ethers");
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
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY;
const ETHERSCAN_ENDPOINT = process.env.ETHERSCAN_ENDPOINT || "https://api-sepolia.etherscan.io/api";
const RPC_URL = process.env.BASE_SEPOLIA_RPC_URL || process.env.RPC_URL;
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

let supabaseDb = null;
async function getSupabaseDb() {
  if (supabaseDb) return supabaseDb;
  supabaseDb = await getSupabaseAdmin(); // same service-role client can query tables
  return supabaseDb;
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

// ---------- Pending results workflow ----------
const PENDING_TABLE = "pending_results";

app.post("/api/pending", async (req, res) => {
  const user = await requireUser(req, res);
  if (!user || user.error) return;
  const meta = user.user_metadata || {};
  if (meta.category !== "Presiding officer") return res.status(403).json({ error: "Only presiding officers can submit" });
  const { data, cid, expectedAgents } = req.body || {};
  if (!data || !cid || !expectedAgents) return res.status(400).json({ error: "data, cid, expectedAgents required" });
  const expected = Number(expectedAgents);
  if (!Number.isFinite(expected) || expected <= 0) return res.status(400).json({ error: "expectedAgents must be >0" });
  try {
    const db = await getSupabaseDb();
    const { data: inserted, error } = await db
      .from(PENDING_TABLE)
      .insert({
        data,
        cid,
        presiding_email: user.email,
        expected_agents: expected,
        division: meta.division || null,
        district: meta.district || null,
        constituency: meta.constituency || null,
        booth: meta.booth || null,
        status: "pending",
      })
      .select()
      .single();
    if (error) throw error;
    return res.json(inserted);
  } catch (err) {
    return res.status(500).json({ error: err.message || "insert failed" });
  }
});

app.get("/api/pending", async (req, res) => {
  const user = await requireUser(req, res);
  if (!user || user.error) return;
  const meta = user.user_metadata || {};
  const role = meta.category;
  let filter = {};
  if (role === "Presiding officer") filter = { presiding_email: user.email };
  else if (role === "Pooling agents") filter = { booth: meta.booth, constituency: meta.constituency, district: meta.district };
  else if (role === "Returning officer") filter = { constituency: meta.constituency, district: meta.district };
  else if (role === "District Commission Office" || role === "District Election Commission Office") filter = { district: meta.district };
  try {
    const db = await getSupabaseDb();
    let query = db.from(PENDING_TABLE).select("*").order("created_at", { ascending: false });
    Object.entries(filter).forEach(([k, v]) => {
      if (v) query = query.eq(k, v);
    });
    const { data: rows, error } = await query;
    if (error) throw error;
    return res.json({ items: rows || [] });
  } catch (err) {
    return res.status(500).json({ error: err.message || "fetch failed" });
  }
});

app.post("/api/pending/sign", async (req, res) => {
  const user = await requireUser(req, res);
  if (!user || user.error) return;
  const meta = user.user_metadata || {};
  if (meta.category !== "Pooling agents") return res.status(403).json({ error: "Only pooling agents can sign" });
  const { id } = req.body || {};
  if (!id) return res.status(400).json({ error: "id required" });
  try {
    const db = await getSupabaseDb();
    const { data: row, error: err1 } = await db.from(PENDING_TABLE).select("*").eq("id", id).single();
    if (err1) throw err1;
    if (row.booth !== meta.booth) return res.status(403).json({ error: "Booth mismatch" });
    const signed = row.signed_agents || [];
    if (signed.includes(user.email)) return res.json({ ok: true, alreadySigned: true });
    signed.push(user.email);
    const { data: updated, error: err2 } = await db
      .from(PENDING_TABLE)
      .update({ signed_agents: signed })
      .eq("id", id)
      .select()
      .single();
    if (err2) throw err2;
    return res.json({ ok: true, row: updated });
  } catch (err) {
    return res.status(500).json({ error: err.message || "sign failed" });
  }
});

app.post("/api/pending/finalize", async (req, res) => {
  const user = await requireUser(req, res);
  if (!user || user.error) return;
  const meta = user.user_metadata || {};
  if (meta.category !== "Presiding officer") return res.status(403).json({ error: "Only presiding officers can finalize" });
  const { id, txHash } = req.body || {};
  if (!id || !txHash) return res.status(400).json({ error: "id and txHash required" });
  try {
    const db = await getSupabaseDb();
    const { data: row, error: err1 } = await db.from(PENDING_TABLE).select("*").eq("id", id).single();
    if (err1) throw err1;
    if (row.presiding_email !== user.email) return res.status(403).json({ error: "Not owner" });
    const signed = row.signed_agents || [];
    if ((signed || []).length < row.expected_agents) return res.status(400).json({ error: "Not enough signatures" });
    const { data: updated, error: err2 } = await db
      .from(PENDING_TABLE)
      .update({ status: "finalized", tx_hash: txHash })
      .eq("id", id)
      .select()
      .single();
    if (err2) throw err2;
    return res.json({ ok: true, row: updated });
  } catch (err) {
    return res.status(500).json({ error: err.message || "finalize failed" });
  }
});

// -------- Records from Etherscan / RPC --------
const recordIface = new Interface([
  "event RecordStored(uint256 id,string data,string cid,address signer,uint64 createdAt)",
  "function storeRecord(string data,string cid)",
]);

function decodeData(dataStr) {
  let parsedData = {};
  try { parsedData = JSON.parse(dataStr); } catch (_) {}
  const div = parsedData.division || "";
  const dist = parsedData.district || "";
  const cons = parsedData.constituency || "";
  const boothVal = parsedData.boothName || parsedData.booth || "";
  const totalVoters = parsedData.totalVoters || "";
  const parties = parsedData.parties || [];
  const totalVotes = Array.isArray(parties) ? parties.reduce((s, p) => s + (p.votes || 0), 0) : "";
  const presidingName = parsedData.officerName || parsedData.presidingOfficer || "";
  const presidingPhone = parsedData.officerPhone || parsedData.presidingPhone || "";
  const agents = parsedData.agents || [];
  return { parsedData, div, dist, cons, boothVal, totalVoters, totalVotes, presidingName, presidingPhone, agents };
}

async function fetchLogs() {
  if (!RPC_URL) return [];
  const body = {
    jsonrpc: "2.0",
    id: 1,
    method: "eth_getLogs",
    params: [
      {
        fromBlock: "0x0",
        toBlock: "latest",
        address: CONTRACT_ADDRESS,
        topics: [recordIface.getEvent("RecordStored").topicHash],
      },
    ],
  };
  const r = await fetch(RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(await r.text());
  const j = await r.json();
  const logs = Array.isArray(j.result) ? j.result : [];
  return logs.map((lg) => {
    try {
      const parsed = recordIface.parseLog({ data: lg.data, topics: lg.topics });
      const dataStr = parsed.args.data;
      const decoded = decodeData(dataStr);
      const time = lg.blockNumber ? new Date(parseInt(lg.timeStamp || lg.blockNumber, 16) * 1000).toISOString() : new Date().toISOString();
      return {
        tx: lg.transactionHash,
        executedAt: time,
        division: decoded.div,
        district: decoded.dist,
        constituency: decoded.cons,
        booth: decoded.boothVal,
        totalVoters: decoded.totalVoters,
        totalVotes: decoded.totalVotes,
        data: dataStr,
        cid: parsed.args.cid,
        signer: parsed.args.signer,
      };
    } catch (err) {
      return null;
    }
  }).filter(Boolean);
}

async function fetchTxListExplorer() {
  const url = `${ETHERSCAN_ENDPOINT}?module=account&action=txlist&address=${CONTRACT_ADDRESS}&sort=desc&apikey=${ETHERSCAN_API_KEY}`;
  const r = await fetch(url);
  if (!r.ok) throw new Error(await r.text());
  const j = await r.json();
  if (j.status !== "1") return [];
  const txs = Array.isArray(j.result) ? j.result : [];
  const selector = recordIface.getFunction("storeRecord").selector;
  return txs.map((tx) => {
    try {
      if (!tx.input || !tx.input.startsWith(selector)) return null;
      const decoded = recordIface.decodeFunctionData("storeRecord", tx.input);
      const dataStr = decoded[0];
      const cid = decoded[1];
      const d = decodeData(dataStr);
      const time = tx.timeStamp ? new Date(Number(tx.timeStamp) * 1000).toISOString() : new Date().toISOString();
      return {
        tx: tx.hash || tx.transactionHash || tx.hash,
        executedAt: time,
        division: d.div,
        district: d.dist,
        constituency: d.cons,
        booth: d.boothVal,
        totalVoters: d.totalVoters,
        totalVotes: d.totalVotes,
        data: dataStr,
        cid,
        signer: tx.from,
      };
    } catch {
      return null;
    }
  }).filter(Boolean);
}

async function fetchTxList() {
  // Merge RPC logs (if any) with explorer txlist decoded inputs, dedupe by tx hash.
  const [logs, explorer] = await Promise.all([
    fetchLogs().catch(() => []),
    fetchTxListExplorer().catch(() => []),
  ]);
  const byTx = new Map();
  [...logs, ...explorer].forEach((r) => {
    if (!r || !r.tx) return;
    if (!byTx.has(r.tx)) byTx.set(r.tx, r);
  });
  return [...byTx.values()];
}

app.get("/api/admin/txlist", async (req, res) => {
  const me = await requireAdmin(req, res);
  if (!me || me.error) return;
  try {
    const list = await fetchTxList();
    return res.json({ items: list.map((r) => r.tx) });
  } catch (err) {
    return res.status(500).json({ error: err.message || "failed to fetch txlist" });
  }
});

app.get("/api/records", async (req, res) => {
  if (!CONTRACT_ADDRESS || !ETHERSCAN_API_KEY) return res.status(500).json({ error: "Explorer API key or contract missing" });
  const { division, district, constituency, booth } = req.query;
  try {
    const mapped = await fetchTxList();
    const filtered = mapped.filter((r) => {
      const divOk = !division || r.division === division;
      const distOk = !district || r.district === district;
      const consOk = !constituency || r.constituency === constituency;
      const boothOk = !booth || r.booth === booth;
      return divOk && distOk && consOk && boothOk;
    });
    return res.json({ items: filtered });
  } catch (err) {
    return res.status(500).json({ error: err.message || "Failed to load records" });
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
