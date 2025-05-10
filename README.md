# Zauth

# Introduction

**Zuitzerland** is a one-of-a-kind "pop-up village" experiment with strong decentralized-access (d/acc) vibes—think Zuzalu with a similar strong privacy focus. At this tiny scale, we've already achieved product–market fit: event organizers are clamoring for a self-hosted tool that lets attendees prove membership without exposing their identity or spamming their inboxes.

---

## Problem

- **Cumbersome ticketing & KYC**  
  Traditional events require issuing, scanning, and managing digital or paper tickets. If you rely on email as an identifier, you end up with long registration forms, spammy follow-up, and privacy risks.
- **Noisy login data**  
  Organizers only want to know "someone from our event just logged in," not collect personal profiles or behavioral data.
- **Repeated proof fatigue**  
  Every time you need to verify a credential—age, nationality, banking status, on-chain activity—you re-run the same verification circuits, wasting time and compute.

---

## Our MVP: Anonymous Set-Membership Login

We've built a **Noir-powered** circuit that simultaneously:

1. **Verifies a user's OAuth2 JWT** (email identity)
2. **Proves membership** in the event's Semaphore identity set

All in **one single zkSNARK proof**, submitted to a centralized verifier.

- **Anonymous:** server only sees "✔️ someone from the event logged in"—no email, no profile.
- **Selective:** only pre-registered event participants can generate a valid proof.
- **Seamless:** attendees use the same email sign-in flow they already know; we just wrap it in a privacy layer.

> **Current traction:** fully working prototype at Zuitzerland. Organizers love it.

---

## Why Now?

- **Privacy is table stakes.** Even small communities demand confidentiality.
- **d/acc momentum.** Experimental villages like Zuzalu/Zuitzerland/ZuBerlin prove there's appetite for decentralized, privacy-preserving tooling.
- **Noir + JWT + Semaphore = sweet spot.** We combine well-tested building blocks into a turnkey solution.

---

## Next Milestones

1. **PCD Database**
   - Clients will store full Proof-Carrying Data (PCD) locally.
   - Server holds only **commitments + salts** in a Merkle tree for **unlinkable**, **auditable**, **private** storage of every proof generated during the event.
2. **Anonymous Transactions**
   - Leverage the same anonymous auth to enable write-access or tokens within the village app without deanonymizing users.
3. **Universal PCD Platform**
   - Extend beyond event login: proofs of age, nationality, bank balances (via Open Banking), on-chain protocol interactions, wallet liquidity, and more.
   - One proof per credential, re-usable and privately verifiable on-chain or off-chain.

---

Join us in making private, unlinkable, verifiable identity as easy as "login with email"—but so much more powerful.

---

https://github.com/user-attachments/assets/9382e71a-2b1f-4950-babf-cee6337d4aad

## Prerequisites

- Node.js (v18 or higher)
- npm or yarn
- Google OAuth2 credentials

## Quick Start

1. **Clone the repository:**

```bash
git clone https://github.com/GustavesCharles/Noir-Hack.git
cd Noir-Hack/zauth
```

2. **Install dependencies:**

```bash
# Server dependencies
cd verifier
npm install

# Client dependencies
cd ../client
npm install
```

3. **Configure environment variables:**

- In `zauth/client/`, create a `.env` file:
  ```env
  VITE_GOOGLE_CLIENT_ID=your-google-client-id
  VITE_REDIRECT_URI=your-redirect-uri
  ```

4. **Start the development servers:**

```bash
# Start the server (from verifier directory)
npm run dev

# Start the client (from client directory)
npm run dev
```

5. **Merkle Proof Configuration:**

- The server computes the Merkle root from whitelisted emails and, after login, returns the Merkle root, the user's index, and proof siblings to the client whenever he gets whitelisted.
- The client uses these values to generate a proof. The `proofConfig.json` file is only a fallback/example; in production, proof data comes from the server.

---

# App Architecture Overview

## 1. Current Implementation

### 1.1. Login + Set-Membership Proof (One-ZK Proof)

- **📧 Identity proof**
  - User authenticates via OAuth2 (e.g. Google/Facebook)
  - Client obtains a JWT, then converts it into a _zkJWT_ proof in Noir
- ** 🚦 Group-membership proof**
  - User has a Semaphore identity (via zk-kit from PSE)
  - Client generates a Semaphore membership proof in Noir
- **Combined proof**
  - Noir circuit takes both the JWT and the Semaphore membership inputs
  - Outputs a single zkSNARK proof that:
    1. The JWT is valid and corresponds to an authenticated email identity
    2. The Semaphore identity is a member of the allowed group
- **Verification**
  - Proof is submitted to a centralized verifier
  - Verifier checks both parts (JWT signature and zkSNARK) in one go

> **What we have today:**
>
> - A fully working login flow with privacy-preserving group-access control, all in one proof.
> - No PCD storage yet—proofs live only on the user's device and are sent directly to the verifier.

## 2. Next Step: PCD Storage

We'll soon introduce **Proof-Carrying Data (PCD)** so that users can keep a local record of their proofs (claims + proofs) and later re-submit them or audit them against a shared Merkle tree. The focus here is on **unlinkability**, **privacy**, and **auditability**.

### 2.1. PCD storage (client-side)

- Stored locally by the client
- Contains full claim + proof + metadata
- user stores a salt for each PCD (salt is derived from a function so as to have a unique master salt to store)

A lightweight JSON blob the client generates and stores:

```jsonc
{
  "version": "1.0",
  "type": "LoginAndMembershipPCD",
  "id": "uuid-v4",
  "claim": {
    "emailHash": "sha256(…)",
    "groupRoot": "0xabc123…",
    "identityCommitment": "0xdef456…"
  },
  "proof": {
    /* single Groth16 proof object */
  },
  "meta": {
    "issuedAt": "2025-05-10T…Z",
    "nonce": "random-32bytes"
  }
}
```

### 2.2 Server-Side Commitment Record

```jsonc
{
  "commitment": "sha256(base64(pcdJSON) ∥ salt)",
  "merkleProof": {
    /* sibling hashes + path indices */
  },
  "treeRoot": "0xdef789…",
  "timestamp": 1715450580
}
```

- **Unlinkability:** fresh salt per PCD → server cannot censor users by pattern
- **Privacy:** server only sees commitments, never raw PCD JSON, and does not store a database of user → PCD
- **Auditability:** public Merkle roots & inclusion proofs

## 3. Future Extensions

- **Hybrid Verifier Model**

  - On-chain smart-contract verifier for blockchain-related PCDs (not yet available)
  - Off-chain server verifier for Web2 proofs (zkJWT, OAuth) (already available)

- **Revocation Lists**
  - Maintain revocation Merkle roots
  - Clients produce non-membership proofs to show a PCD hasn't been revoked

## 4. Notes on constraint counts, proving times & UX considerations

![Capture d'écran 2025-05-10 à 00 54 18](https://github.com/user-attachments/assets/fa73bb55-d5d4-43d1-bc30-1a102ac3bc37)

We can see that the two most ressource intesive functions are the ones from the JWT library. It will be hard for us to bring this down, as it is an external library. We also note that our proving takes approximately 10 seconds. This is clearly above a usual Web2 UX experience, and thus we will explore alternative solutions for more comupte intensive proofs, like delegating to a coSNARK network, such as TACEO's.

## 4. Next Actions

1. Build client-side PCD generator & local database
2. Implement server Merkle-tree API (append & query commitments)
3. Update README with:
   - Quickstart & usage examples
   - Demo links / videos / deployed contracts
