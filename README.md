<a id="readme-top"></a>

[![Contributors][contributors-shield]][contributors-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![Last commit][last-commit-shield]][commits-url]

<br />
<div align="center">
  <h1 align="center">IPFS Pin Server</h1>
  <p align="center">
    The backend API for the Stop Vote Rigging project. It stores polling station result sheets on IPFS, runs a multi-signature approval flow for results, and reads the final records back from Ethereum.
    <br /><br />
    <a href="#getting-started"><strong>Get started »</strong></a>
    <br /><br />
    <a href="#api-endpoints">API</a>
    &middot;
    <a href="https://github.com/rafsunsheikh/ipfs_pin_server/issues">Report Bug</a>
    &middot;
    <a href="https://github.com/rafsunsheikh/ipfs_pin_server/issues">Request Feature</a>
  </p>
</div>

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#how-a-result-moves-through-the-system">How A Result Moves Through The System</a></li>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li><a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
        <li><a href="#environment-variables">Environment Variables</a></li>
        <li><a href="#supabase-tables">Supabase Tables</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#api-endpoints">API Endpoints</a></li>
    <li><a href="#security-notes">Security Notes</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

## About The Project

Election results in many places are written on paper at each polling station and then passed up a chain of officials. Every hand-off is a chance to change the numbers. The Stop Vote Rigging project tries to make that harder: the result sheet from each polling booth is stored on IPFS, several polling agents must sign off on it, and the final record is written to an Ethereum smart contract where anyone can check it later.

This repository is the small Node.js server that sits between the web app and those outside services. It does four jobs:

* **Pins files and JSON to IPFS** through [Pinata][pinata-url], so the browser never needs the Pinata keys. It returns the content ID (CID) of each upload.
* **Checks who is calling.** Every protected route reads a [Supabase][supabase-url] login token. One admin account (set by email) can approve or reject new users, and every other user is limited by their election role and location.
* **Runs the approval flow for results.** A presiding officer submits a result, the polling agents for that booth sign it, and the officer finalises it once enough agents have signed.
* **Reads the on-chain records.** It decodes `RecordStored` events and `storeRecord` transactions from the contract, using a JSON-RPC node and the Etherscan API, and lets the app filter them by division, district, constituency and booth.

The server knows these election roles: `Pooling agents`, `Presiding officer`, `Returning officer`, `District Commission Office`, `District Election Commission Office` and `Election Commission HQ`. These strings are used exactly as written in the code, so they are shown here the same way.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### How A Result Moves Through The System

1. The admin approves the accounts of a presiding officer and the polling agents for a booth.
2. The presiding officer uploads the scanned result sheet. `POST /api/pin` stores it on IPFS and returns its CID.
3. The presiding officer submits the result with `POST /api/pending`, giving the result data, the CID and how many agent signatures are needed.
4. Each polling agent for the same booth signs with `POST /api/pending/sign`.
5. When the number of signatures reaches the target, the presiding officer writes the record on-chain from the app, then calls `POST /api/pending/finalize` with the transaction hash. The server marks the result as finalised and copies it into the approved results table.
6. Anyone can list approved results with `GET /api/approved` or the on-chain records with `GET /api/records`.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

* [![Node.js][node-shield]][node-url]
* [![Express][express-shield]][express-url]
* [![Supabase][supabase-shield]][supabase-url]
* [![IPFS via Pinata][ipfs-shield]][pinata-url]
* [![ethers.js][ethers-shield]][ethers-url]

Other packages: `multer` for file uploads, `form-data` and `node-fetch` for calls to Pinata and Etherscan, `cors`, and `dotenv`.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Getting Started

### Prerequisites

* Node.js and npm
* A Pinata account (a JWT, or an API key and secret)
* A Supabase project with Auth turned on and the two tables described below
* For the on-chain record routes: the address of the deployed record contract, an Etherscan API key and an Ethereum RPC URL. The defaults point at the Sepolia test network.

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/rafsunsheikh/ipfs_pin_server.git
   cd ipfs_pin_server
   ```
2. Install the packages
   ```sh
   npm install
   ```
3. Create a `.env` file in the project folder with the variables listed below. Keep this file out of git.
4. Start the server
   ```sh
   npm start
   ```
   You should see `Pin server listening on http://localhost:3001` (or the port you set).

### Environment Variables

| Variable | Needed for | Notes |
|----------|------------|-------|
| `PINATA_JWT` | IPFS uploads | Used first if set. |
| `PINATA_API_KEY`, `PINATA_API_SECRET` | IPFS uploads | Used when `PINATA_JWT` is not set. |
| `SUPABASE_URL` | Login checks, results | Your Supabase project URL. |
| `SUPABASE_SERVICE_ROLE_KEY` | Login checks, results | Server-side key. Never send it to the browser. |
| `ADMIN_EMAIL` | Admin routes | The one account allowed to use `/api/admin/*`. |
| `CONTRACT_ADDRESS` | On-chain records | Address of the contract that stores the records. |
| `ETHERSCAN_API_KEY` | On-chain records | Needed by `/api/records`. |
| `ETHERSCAN_ENDPOINT` | On-chain records | Defaults to `https://api-sepolia.etherscan.io/api`. |
| `SEPOLIA_RPC_URL` | On-chain records | Checked first. Falls back to `RPC_URL`, then `BASE_SEPOLIA_RPC_URL`. |
| `PORT` or `PIN_SERVER_PORT` | Server | Defaults to `3001`. |

### Supabase Tables

The repo does not include a database schema, but the code reads and writes these columns:

* `pending_results`: `id`, `data`, `cid`, `presiding_email`, `expected_agents`, `signed_agents`, `division`, `district`, `constituency`, `booth`, `status`, `tx_hash`, `created_at`
* `approved_results`: `data`, `cid`, `presiding_email`, `expected_agents`, `signed_agents`, `division`, `district`, `constituency`, `booth`, `tx_hash`, `status`, `created_at`

User details such as role, division, district, constituency, booth and approval status are read from each Supabase user's `user_metadata` (`category`, `division`, `district`, `constituency`, `booth`, `approved`, and so on).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Usage

Pin a scanned result sheet to IPFS:

```sh
curl -F "file=@result-sheet.jpg" http://localhost:3001/api/pin
```

The reply holds the CID, the size and the time from Pinata:

```json
{ "cid": "Qm...", "size": 12345, "timestamp": "..." }
```

List the on-chain records for one district:

```sh
curl "http://localhost:3001/api/records?district=Dhaka"
```

Routes that need a login take a Supabase access token:

```sh
curl -H "Authorization: Bearer <supabase-access-token>" http://localhost:3001/api/pending
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## API Endpoints

| Method | Path | Who can call it | What it does |
|--------|------|-----------------|--------------|
| `POST` | `/api/pin` | Anyone | Uploads one file (form field `file`) to IPFS and returns its CID. |
| `POST` | `/api/pin-json` | Anyone | Sends the JSON body to Pinata and returns its CID. |
| `POST` | `/api/pending` | Presiding officer | Submits a result (`data`, `cid`, `expectedAgents`) for approval. |
| `GET` | `/api/pending` | Any logged-in user | Lists pending results, limited by the caller's role and location. |
| `POST` | `/api/pending/sign` | Polling agent | Signs a pending result for the agent's own booth. |
| `POST` | `/api/pending/finalize` | Presiding officer who submitted it | Finalises a result with its `txHash` once enough agents have signed. |
| `GET` | `/api/approved` | Anyone | Lists approved results. Filters: `division`, `district`, `constituency`, `booth`. |
| `GET` | `/api/records` | Anyone | Lists records decoded from the chain, with the same filters. |
| `GET` | `/api/txlist` | Anyone | Lists the transaction hashes of the stored records. |
| `GET` | `/api/search/users` | Any logged-in user | Searches users the caller is allowed to see (by district or constituency). |
| `GET` | `/api/admin/pending-users` | Admin | Lists users waiting for approval. |
| `GET` | `/api/admin/users` | Admin | Lists all users, with search and location filters. |
| `POST` | `/api/admin/approve` | Admin | Approves a user (`approve: true`) or deletes them (`approve: false`). |
| `GET` | `/api/admin/txlist` | Admin | Same as `/api/txlist`, behind the admin check. |

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Security Notes

This server was built for a research prototype on a test network. Before using it with real data, keep in mind:

* CORS is open to every origin (`origin: "*"`).
* `/api/pin` and `/api/pin-json` do not ask for a login, so anyone who can reach the server can upload to your Pinata account.
* Results and records written to IPFS and to a public blockchain are public and cannot be removed. Do not store private personal data in them.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Contact

Rafsun Sheikh: [GitHub][github-url] &middot; [LinkedIn][linkedin-url] &middot; [Website][website-url]

Project link: [https://github.com/rafsunsheikh/ipfs_pin_server][repo-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

[contributors-shield]: https://img.shields.io/github/contributors/rafsunsheikh/ipfs_pin_server.svg?style=for-the-badge
[contributors-url]: https://github.com/rafsunsheikh/ipfs_pin_server/graphs/contributors
[stars-shield]: https://img.shields.io/github/stars/rafsunsheikh/ipfs_pin_server.svg?style=for-the-badge
[stars-url]: https://github.com/rafsunsheikh/ipfs_pin_server/stargazers
[issues-shield]: https://img.shields.io/github/issues/rafsunsheikh/ipfs_pin_server.svg?style=for-the-badge
[issues-url]: https://github.com/rafsunsheikh/ipfs_pin_server/issues
[last-commit-shield]: https://img.shields.io/github/last-commit/rafsunsheikh/ipfs_pin_server.svg?style=for-the-badge
[commits-url]: https://github.com/rafsunsheikh/ipfs_pin_server/commits/master
[repo-url]: https://github.com/rafsunsheikh/ipfs_pin_server
[node-shield]: https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white
[node-url]: https://nodejs.org/
[express-shield]: https://img.shields.io/badge/Express-000000?style=for-the-badge&logo=express&logoColor=white
[express-url]: https://expressjs.com/
[supabase-shield]: https://img.shields.io/badge/Supabase-3FCF8E?style=for-the-badge&logo=supabase&logoColor=white
[supabase-url]: https://supabase.com/
[ipfs-shield]: https://img.shields.io/badge/IPFS%20(Pinata)-65C2CB?style=for-the-badge&logo=ipfs&logoColor=white
[pinata-url]: https://pinata.cloud/
[ethers-shield]: https://img.shields.io/badge/ethers.js%20v6-2535A0?style=for-the-badge&logo=ethereum&logoColor=white
[ethers-url]: https://docs.ethers.org/v6/
[github-url]: https://github.com/rafsunsheikh
[linkedin-url]: https://www.linkedin.com/in/mdrafsunsheikh/
[website-url]: https://rafsunsheikh.github.io
