# Zauth

# App Architecture Overview

## 1. Current Implementation

### 1.1. Login + Set-Membership Proof (One-ZK Proof)
- **Identity proof**  
  - User authenticates via OAuth2 (e.g. Google/Facebook)  
  - Client obtains a JWT, then converts it into a _zkJWT_ proof in Noir
- **Group-membership proof**  
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
> - A fully working login flow with privacy-preserving group-access control, all in one proof.  
> - No PCD storage yet—proofs live only on the user’s device and are sent directly to the verifier.

---

## 2. Next Step: PCD Storage

We’ll soon introduce **Proof-Carrying Data (PCD)** so that users can keep a local record of their proofs (claims + proofs) and later re-submit them or audit them against a shared Merkle tree. The focus here is on **unlinkability**, **privacy**, and **auditability**.

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
  "proof": { /* single Groth16 proof object */ },
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
  "merkleProof": { /* sibling hashes + path indices */ },
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
  - Off-chain server verifier for Web2 proofs (zkJWT, OAuth)  (already available)

- **Revocation Lists**  
  - Maintain revocation Merkle roots  
  - Clients produce non-membership proofs to show a PCD hasn’t been revoked  

## 4. Next Actions

1. Build client-side PCD generator & local database  
2. Implement server Merkle-tree API (append & query commitments)  
3. Update README with:  
   - Quickstart & usage examples  
   - Demo links / videos / deployed contracts  
   - Notes on constraint counts, proving times & UX considerations 
