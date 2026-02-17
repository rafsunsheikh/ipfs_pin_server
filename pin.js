const express = require("express");
const multer = require("multer");
const FormData = require("form-data");
const fetch = require("node-fetch");
const cors = require("cors");
require("dotenv").config();

const upload = multer();
const app = express();
app.use(cors());

const PINATA_FILE_ENDPOINT = "https://api.pinata.cloud/pinning/pinFileToIPFS";
const PINATA_JSON_ENDPOINT = "https://api.pinata.cloud/pinning/pinJSONToIPFS";

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
