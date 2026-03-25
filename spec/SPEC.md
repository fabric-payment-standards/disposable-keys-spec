---
document: disposable-keys/spec.md
title: MPC System Architecture for Disposable Keys (MPC-001)
description: Formal specification of a distributed MPC threshold signature system for disposable key usage
spec_id: FPSF-MPC-001
version: 1.0.0
status: Draft
date: 2026-03-25
author: Adalton Reis <reis@fabricpaymentstandards.org>
organization: Fabric Payment Standards Foundation
contact: contact@fabricpaymentstandards.org
license: Apache-2.0
---
 
# FPSF-MPC-001 - MPC System Architecture for Disposable Keys (MPC-001) — Formal Specification 

## Table of Contents

1. [Overview and Purpose](#1-overview-and-purpose)
2. [Terminology and Definitions](#2-terminology-and-definitions)
3. [Trust Model and Threat Model](#3-trust-model-and-threat-model)
4. [Key Taxonomy](#4-key-taxonomy)
5. [System Architecture](#5-system-architecture)
6. [Cryptographic Foundations](#6-cryptographic-foundations)
7. [Network Layer and Transport Security](#7-network-layer-and-transport-security)
8. [Identity and Admission Control](#8-identity-and-admission-control)
9. [Coordinator Protocol](#9-coordinator-protocol)
10. [Node Lifecycle](#10-node-lifecycle)
11. [Group Formation Protocol](#11-group-formation-protocol)
12. [Distributed Key Generation (DKG)](#12-distributed-key-generation-dkg)
13. [Threshold Signature Protocol (FROST)](#13-threshold-signature-protocol-frost)
14. [Key Share Storage and Reconstruction](#14-key-share-storage-and-reconstruction)
15. [Public-Facing REST API](#15-public-facing-rest-api)
16. [Request Authentication Model](#16-request-authentication-model)
17. [Account and Pseudo-Account Model](#17-account-and-pseudo-account-model)
18. [Disposable Key Lifecycle](#18-disposable-key-lifecycle)
19. [Anti-Collusion Mechanisms](#19-anti-collusion-mechanisms)
20. [Observability and Uptime Tracking](#20-observability-and-uptime-tracking)
21. [Fault Tolerance and Recovery](#21-fault-tolerance-and-recovery)
22. [Data Minimisation and Privacy](#22-data-minimisation-and-privacy)
23. [Message Formats and Schemas](#23-message-formats-and-schemas)
24. [Error Codes and Failure Semantics](#24-error-codes-and-failure-semantics)
25. [Security Considerations](#25-security-considerations)
26. [Implementation Guidance](#26-implementation-guidance)
27. [Open Questions and Future Work](#27-open-questions-and-future-work)

---

## 1. Overview and Purpose

This document specifies a multi-party computation (MPC) threshold signature system whose purpose is to generate, manage, and operate **disposable Ed25519 signing keys** on behalf of users. No single participant node, nor the coordinator, ever possesses a complete private key. Private key material exists only as secret shares distributed across a dynamically formed group of participant nodes, and is discarded upon user request.

The system exposes a **public REST API** through which users can:

- Register a root-key account (implicitly, on first use)
- Create disposable Ed25519 key pairs (key generation via MPC)
- Sign arbitrary messages with a previously created disposable key
- Destroy disposable keys

All user requests are **self-authenticated** through canonicalized and signed JSON payloads. There is no session state, no username/password, and no bearer token. Authentication is structural.

---

## 2. Terminology and Definitions

| Term | Definition |
|------|-----------|
| **Root Key** | An Ed25519 key pair generated and held exclusively by the user offline. Its public key serves as the identifier for the user's pseudo-account. |
| **Sub Key** | An Ed25519 key pair held online on the user's device. Authorized by the root key. Used to sign all API requests. |
| **Disposable Key** | An Ed25519 key pair generated entirely within the MPC system via DKG. The private key never exists in assembled form. Used to sign messages and then discarded. |
| **Node** | A participant in the MPC network. Holds shares of disposable keys. Communicates over mTLS-secured WebSocket connections. |
| **Coordinator** | A central server that admits nodes, orchestrates group formation, dispatches jobs (DKG and signing), and monitors uptime. |
| **Group** | A temporary set of `n` nodes assigned to manage one disposable key. Formed on demand. Dissolved after key destruction. |
| **Threshold** | The minimum number `t` of nodes required to produce a valid signature. `t ≤ n`. |
| **DKG** | Distributed Key Generation — the protocol by which a group of nodes collectively creates a key pair such that no single node learns the full private key. |
| **FROST** | Flexible Round-Optimized Schnorr Threshold signatures — the signing protocol used. Compatible with Ed25519. |
| **Share** | A node's portion of a distributed secret (the private key scalar). |
| **Authorization Token** | A signed statement by a root key certifying that a given sub key is permitted to act on the root key's account. |
| **Canonical JSON** | JSON serialized per RFC 8785 (JCS — JSON Canonicalization Scheme). Required for deterministic signing. |
| **mTLS** | Mutual TLS — both sides of a connection present and verify X.509 certificates. |
| **CA** | Certificate Authority — the central institution that issues and revokes node certificates. |
| **VRF** | Verifiable Random Function — a function producing a pseudorandom output with a cryptographic proof of correctness. Used for anti-collusion group selection. |
| **Key ID** | A stable, opaque identifier for a disposable key. Returned at creation time. Used to reference the key in subsequent requests. |
| **Account ID** | The SHA-256 hash of a root key's public key, encoded in lowercase hexadecimal. Serves as the account identifier. |

---

## 3. Trust Model and Threat Model

### 3.1 Trusted Parties

- **The CA / Issuing Institution**: Issues node certificates and sub-key authorization tokens. Trusted to not issue certificates to colluding parties. Its compromise is out of scope.
- **The Coordinator**: Trusted to dispatch jobs fairly and not to permanently bias group selection. Its compromise must not expose key material (it never holds shares).

### 3.2 Untrusted Parties

- **Individual Nodes**: No single node is trusted with a complete key. Up to `t-1` nodes may be compromised without affecting security.
- **API Callers**: Considered untrusted until they present a valid, fresh, self-signed request.

### 3.3 Threat Model

| Threat | Mitigation |
|--------|-----------|
| Node compromise (fewer than `t` nodes) | Threshold property — partial shares are useless |
| Node collusion | VRF-based group assignment; nodes do not know each other's identities across groups |
| Coordinator compromise | Coordinator cannot assemble key material; logs are append-only and verifiable |
| Replay attacks on API | Nonce + timestamp in every request envelope |
| Root key exfiltration | Root key never contacts the API; all requests signed by sub keys |
| Share exfiltration via network | mTLS with client certificates; all inter-node messages are encrypted |
| Long-lived key exposure | Disposable keys are deleted on demand; shares are wiped on destruction |
| Side-channel share reconstruction | Shares stored encrypted at rest; memory-safety enforced by implementation |

---

## 4. Key Taxonomy

The system uses exactly three classes of key, each with a distinct role. They are not interchangeable.

```
┌─────────────────────────────────────────────────────────────────┐
│  User Domain (off-system)                                       │
│                                                                 │
│  Root Key (Ed25519)  ──signs──>  Sub-Key Authorization Token    │
│  Lives offline                                                  │
│                                                                 │
│  Sub Key (Ed25519)   ──signs──>  All API Requests               │
│  Lives on user device                                           │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ HTTPS REST
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  MPC System                                                     │
│                                                                 │
│  Disposable Key (Ed25519)                                       │
│  - Public key: visible, returned to user on creation            │
│  - Private scalar: never assembled; held as shares by nodes     │
│  - Identified by Key ID                                         │
│  - Associated with a pseudo-account (via root key pub key)      │
└─────────────────────────────────────────────────────────────────┘
```

### 4.1 Root Key

- Ed25519 key pair.
- Private key: held by user, **never transmitted anywhere**.
- Public key: registered implicitly when the user makes their first API call.
- Purpose: signs Sub-Key Authorization Tokens only.
- **The MPC system MUST reject any request whose signer is a known root key public key.**

### 4.2 Sub Key

- Ed25519 key pair.
- Private key: held on user's online device.
- Public key: carried in every API request alongside an Authorization Token.
- Authorized by a root key Authorization Token, presented in every request.
- Multiple sub keys may be authorized per root key.
- **Sub keys are the sole permitted signers of API requests.**

### 4.3 Disposable Key

- Ed25519 key pair generated by FROST DKG.
- Private scalar: split into `n` shares across a group of nodes. Never assembled.
- Public key: deterministic output of DKG; returned to the user upon creation.
- Identified by a system-assigned Key ID (UUID v4).
- Lifecycle: created → used (zero or more times) → destroyed.

---

## 5. System Architecture

### 5.1 Component Diagram

```
                     ┌────────────────────┐
                     │   User / Client    │
                     │  (Root Key offline)│
                     │  (Sub Key online)  │
                     └────────┬───────────┘
                              │ HTTPS REST (RFC 8785 signed JSON)
                              ▼
                ┌─────────────────────────────┐
                │         API Gateway         │
                │  - TLS termination          │
                │  - Canonicalization verify  │
                │  - Request validation       │
                │  - Rate limiting            │
                └──────────────┬──────────────┘
                               │ Internal gRPC / HTTP
                               ▼
                ┌─────────────────────────────┐
                │        Coordinator          │
                │  - Node registry            │
                │  - Group formation (VRF)    │
                │  - Job dispatch             │
                │  - Uptime monitor           │
                │  - Key-ID → Group mapping   │
                └──────┬──────────────┬───────┘
                       │ mTLS WebSocket│
          ┌────────────┴──┐     ┌──────┴──────────-──┐
          │   Node A      │     │   Node B           │
          │  (share store)│ ... │  (share store)     │
          └───────────────┘     └────────────────────┘
                    (up to hundreds of nodes)
```

### 5.2 Component Responsibilities

**API Gateway**
- Terminates HTTPS from clients.
- Validates RFC 8785 canonical JSON structure.
- Verifies sub-key signature over the request body.
- Verifies Authorization Token (root key signature over sub-key public key).
- Routes valid requests to the Coordinator.
- Returns structured error responses.

**Coordinator**
- Maintains a live registry of connected nodes and their health status.
- Selects node groups using a Verifiable Random Function seeded by a job-specific seed.
- Dispatches DKG jobs (key creation) and signing jobs.
- Stores the mapping of `Key ID → {group node IDs, threshold params, public key}`.
- Monitors node liveness via heartbeat over persistent WebSocket.
- Manages node admission (certificate validation, revocation checking).
- Produces signed, append-only audit logs.

**Participant Nodes**
- Maintain a persistent mTLS WebSocket connection to the Coordinator.
- Participate in DKG and FROST signing protocols when selected.
- Store encrypted key shares for assigned disposable keys.
- Can participate in multiple concurrent groups.
- Report health metrics to the Coordinator.
- Wipe shares upon receiving a verified destruction command.

### 5.3 Persistence Requirements

| Entity | Where Stored | Notes |
|--------|-------------|-------|
| Node mTLS certificate | Node local disk | Issued by CA |
| Key shares | Node encrypted storage | Encrypted with node key; never in plaintext |
| Key ID → Group mapping | Coordinator database | Authoritative record |
| Pseudo-account (root pub key hash) | Coordinator database | Minimal — hash only |
| Sub-key authorization tokens | Not stored | Verified on each request; not retained |
| Audit log | Append-only store | Coordinator signs each entry |

---

## 6. Cryptographic Foundations

### 6.1 Signature Scheme

All keys in this system are **Ed25519** (Edwards-curve Digital Signature Algorithm over Curve25519). The threshold signing protocol is **FROST (Flexible Round-Optimized Schnorr Threshold Signatures)** as specified in IETF draft-irtf-cfrg-frost.

FROST properties relevant to this system:
- **Two-round protocol** (Commitment round + Signature round).
- Produces a **standard Ed25519-compatible signature** — verifiers need not be FROST-aware.
- Supports **t-of-n** threshold: any `t` of `n` participants can sign; fewer than `t` learn nothing about the private key.
- Non-interactive aggregation: the coordinator (or any party) can aggregate partial signatures without learning the private key.

### 6.2 Threshold Parameters

The threshold `(t, n)` is **configurable per key-creation request**, subject to system policy bounds:

- Minimum `t`: 2 (single-node signing is disallowed regardless of request)
- Minimum `n`: `t + 1` (at least one redundant node)
- Maximum `n`: Coordinator policy (recommended: 7–15 for latency reasons; up to available live nodes)
- Default if not specified: `(t=3, n=5)`

The chosen `(t, n)` is recorded in the Key ID metadata and is immutable after key creation.

### 6.3 Distributed Key Generation

DKG uses **Pedersen DKG**, which is compatible with FROST. Each node:
1. Generates a random polynomial of degree `t-1`.
2. Broadcasts commitments to polynomial coefficients (using Pedersen commitments).
3. Sends secret shares to every other group member (encrypted point-to-point over the existing mTLS WebSocket channel).
4. Verifies received shares against commitments.
5. Derives its final share as the sum of received contributions.

The **group public key** is derived from the broadcasted commitments and is identical to what a standard Ed25519 key generation would produce for the corresponding private key.

### 6.4 Key IDs

A Key ID is a **UUID v4** assigned by the Coordinator at job creation time, before DKG begins. It is returned to the user in the response. The Key ID is used to:
- Look up which nodes hold shares.
- Reference the key in signing and destruction requests.
- Associate the key with a pseudo-account.

### 6.5 Authorization Token Format

An Authorization Token is an Ed25519 signature by the root key over the following canonical structure:

```json
{
  "version": "1",
  "type": "sub_key_authorization",
  "root_key_pub": "<base64url-encoded root public key>",
  "sub_key_pub": "<base64url-encoded sub key public key>",
  "issued_at": "<ISO 8601 UTC timestamp>",
  "expires_at": "<ISO 8601 UTC timestamp, optional>"
}
```

This object is serialized using RFC 8785 before signing. The resulting signature is base64url-encoded and included in every API request envelope alongside the token payload.

The MPC system:
- Verifies the token signature against the root key public key.
- Verifies that the request signer matches `sub_key_pub` in the token.
- **Does not store the token.** Verification is stateless.
- **Does not accept requests signed by the root key itself** (checked against the known set of registered root key public key hashes).

---

## 7. Network Layer and Transport Security

### 7.1 External API (Client → API Gateway)

- Protocol: HTTPS (TLS 1.3 minimum).
- No client certificate required (public-facing).
- Authentication is at the application layer via signed request envelopes (Section 16).

### 7.2 Internal Network (Coordinator ↔ Nodes)

- Protocol: **WebSocket over TLS 1.3 (WSS)** with **mutual TLS (mTLS)**.
- Both the Coordinator and each Node present X.509 certificates issued by the CA.
- The Coordinator validates the node certificate against the CA root and checks a CRL/OCSP endpoint before accepting the connection.
- Node certificates contain:
  - `SubjectPublicKeyInfo`: the node's long-term identity key (Ed25519 preferred, RSA-2048 minimum for compatibility)
  - `SubjectAltName`: node identifier (opaque, assigned by CA)
  - `KeyUsage`: `digitalSignature`, `keyAgreement`
  - Validity period: recommended 90 days, renewed by CA
- **Nodes connect to the Coordinator; Coordinator never initiates connections to nodes.**

### 7.3 WebSocket Framing and Message Format

All WebSocket messages are **binary frames** carrying JSON payloads encoded as UTF-8. Each message has the envelope:

```json
{
  "msg_id": "<UUID v4>",
  "msg_type": "<type string>",
  "sender_node_id": "<opaque node identifier>",
  "timestamp": "<ISO 8601 UTC>",
  "payload": { ... },
  "sig": "<base64url Ed25519 signature over canonical JSON of all other fields>"
}
```

All participants verify `sig` before processing any message. Messages with invalid signatures are silently dropped and the anomaly is logged.

### 7.4 Connection Management

- Nodes maintain a **persistent WebSocket connection** to the Coordinator.
- Heartbeat: nodes send a `PING` message every 10 seconds; Coordinator expects a `PONG` within 5 seconds.
- If three consecutive heartbeats are missed, the node is marked **DEGRADED**.
- If five consecutive heartbeats are missed, the node is marked **OFFLINE**.
- Reconnection: nodes implement exponential backoff (base 1s, max 60s, jitter ±20%).
- Nodes rejoin automatically after reconnection; the Coordinator re-validates the mTLS certificate on reconnect.

---

## 8. Identity and Admission Control

### 8.1 Node Identity

Each node's identity is its **certificate subject**, issued by the CA. The CA is operated by the central institution. The process is:

1. Node operator generates a key pair and submits a CSR to the CA.
2. CA verifies operator identity through out-of-band means.
3. CA issues certificate with appropriate extensions (Section 7.2).
4. Node presents certificate on WebSocket connection; Coordinator validates.
5. Node is added to the **node registry** in `ONLINE` state.

### 8.2 Node Revocation

- The CA maintains a **Certificate Revocation List (CRL)** and an **OCSP responder**.
- The Coordinator checks certificate validity at connection time and periodically (every 5 minutes) for already-connected nodes.
- On revocation detection: node is marked `REVOKED`, disconnected, and removed from all future group assignments.
- Shares held by a revoked node become inaccessible. Recovery options are described in Section 21.

### 8.3 User Sub-Key Authorization

There is no registration step for sub keys. Authorization is carried inline with every request (Section 16). The Coordinator tracks which root key hashes have been seen, creating pseudo-accounts implicitly.

---

## 9. Coordinator Protocol

### 9.1 State Machine

The Coordinator maintains a state machine per job (key creation or signing):

```
PENDING → GROUPS_ASSIGNED → DKG_IN_PROGRESS → COMPLETE
                                    │
                                    └──> FAILED (retry or abort)
```

For signing jobs:
```
PENDING → GROUP_NOTIFIED → COMMITMENT_ROUND → SIGNATURE_ROUND → COMPLETE
                                    │
                                    └──> FAILED → RETRY or ABORT
```

### 9.2 Job Queue

- The Coordinator maintains a persistent job queue (ordered by arrival time).
- Each job has a maximum lifetime (TTL): DKG jobs: 30 seconds; Signing jobs: 15 seconds.
- Expired jobs are marked `FAILED` and the client receives an error response.
- Jobs are retried at most once before failure is returned to the client.

### 9.3 Coordinator API (Internal, WebSocket Messages)

| Message Type | Direction | Description |
|-------------|-----------|-------------|
| `NODE_REGISTER` | Node → Coordinator | Initial handshake after connection |
| `NODE_PING` | Node → Coordinator | Heartbeat |
| `NODE_PONG` | Coordinator → Node | Heartbeat acknowledgment |
| `JOB_ASSIGN` | Coordinator → Node | Assignment to a DKG or signing group |
| `JOB_DECLINE` | Node → Coordinator | Node cannot accept job (load, error) |
| `DKG_COMMITMENT` | Node → Coordinator | Broadcast DKG polynomial commitments |
| `DKG_SHARE` | Node → Node (relayed) | Encrypted share for a specific peer |
| `DKG_COMPLETE` | Node → Coordinator | DKG finished successfully on this node |
| `DKG_ABORT` | Node → Coordinator | DKG error on this node |
| `SIGN_NONCE_COMMIT` | Node → Coordinator | FROST round 1: nonce commitment |
| `SIGN_PARTIAL_SIG` | Node → Coordinator | FROST round 2: partial signature |
| `SIGN_ABORT` | Node → Coordinator | Signing error on this node |
| `KEY_DESTROY` | Coordinator → Node | Instruct node to wipe a specific share |
| `KEY_DESTROY_ACK` | Node → Coordinator | Share wiped confirmation |
| `HEALTH_REPORT` | Node → Coordinator | CPU, memory, active groups, error counts |

---

## 10. Node Lifecycle

### 10.1 States

```
CONNECTING → ONLINE → DEGRADED → OFFLINE
                │                   │
                ▼                   ▼
            REVOKED             RECONNECTING
```

| State | Meaning |
|-------|---------|
| `CONNECTING` | WebSocket handshake in progress; mTLS certificate being verified |
| `ONLINE` | Fully connected; eligible for group assignment |
| `DEGRADED` | Missed 3–4 consecutive heartbeats; not assigned to new groups |
| `OFFLINE` | Missed 5+ heartbeats or connection dropped; shares considered unavailable |
| `REVOKED` | Certificate revoked; permanently excluded |
| `RECONNECTING` | Node is attempting to re-establish connection |

### 10.2 Group Participation Concurrency

A node may participate in multiple concurrent groups simultaneously. The Coordinator limits concurrent group membership to a configurable maximum per node (recommended: 10), to prevent resource exhaustion. A node reports its current load in `HEALTH_REPORT` messages, and the Coordinator uses this in group selection scoring.

### 10.3 Node Departure

When a node disconnects cleanly:
- It sends a `NODE_LEAVE` message.
- The Coordinator updates its state to `OFFLINE`.
- Any in-flight jobs involving that node are assessed: if `t` nodes remain available for the group, the job can continue. Otherwise it is aborted and retried with a new group.
- The node's shares remain on disk (encrypted) until the node reconnects and the shares are no longer needed, or until explicit destruction.

---

## 11. Group Formation Protocol

### 11.1 Principles

- Groups are **ephemeral**: formed for a specific key, dissolved conceptually at key destruction.
- Groups are **lightweight**: formation is a Coordinator-side selection plus a `JOB_ASSIGN` broadcast.
- Nodes **do not need to know each other's real identities**. All inter-node DKG traffic (specifically `DKG_SHARE` messages) is **relayed through the Coordinator** using opaque session-scoped node handles, preventing nodes from correlating peer identities across groups.

### 11.2 Group Selection Algorithm

Group selection MUST use a **Verifiable Random Function (VRF)** to provide:
- Non-predictability: no entity can predict which nodes will be selected before the fact.
- Verifiability: after selection, any party can verify the selection was correct.

**Algorithm:**

1. Coordinator generates a random `job_seed` (32 bytes, CSPRNG).
2. Coordinator computes `vrf_output = VRF_prove(coordinator_private_key, job_seed || key_id)`.
3. Coordinator sorts eligible (ONLINE, under load limit) nodes by `HMAC(vrf_output, node_id)`.
4. Selects the top `n` nodes from the sorted list.
5. Publishes `job_seed`, `vrf_output`, and `vrf_proof` to the audit log so selection can be retrospectively verified.

This prevents the Coordinator from selectively biasing groups while maintaining central control.

### 11.3 Group Metadata

For each active disposable key, the Coordinator stores:

```json
{
  "key_id": "<UUID v4>",
  "account_id": "<hex SHA-256 of root pub key>",
  "threshold": { "t": 3, "n": 5 },
  "group_node_handles": ["<opaque handle A>", "..."],
  "group_public_key": "<base64url encoded Ed25519 public key>",
  "created_at": "<ISO 8601>",
  "state": "ACTIVE | SIGNING | DESTROYING | DESTROYED"
}
```

Node handles are session-scoped opaque tokens — they cannot be correlated with node identities by an observer of this metadata.

---

## 12. Distributed Key Generation (DKG)

### 12.1 Protocol (Pedersen DKG)

**Precondition:** A group of `n` nodes has been assigned to a DKG job by the Coordinator.

**Round 1 — Commitments:**
1. Each node `i` samples a random polynomial `f_i(x)` of degree `t-1` over the scalar field of Ed25519.
2. Node `i` computes Pedersen commitments `C_i_j = f_i(j) * G` for `j = 0..t-1`.
3. Node `i` broadcasts `{commitments: [C_i_0, ..., C_i_(t-1)]}` to all group members (relayed via Coordinator).

**Round 2 — Share Distribution:**
1. Each node `i` computes shares `s_i_j = f_i(j)` for each peer `j` (including itself where `j = i`).
2. Node `i` encrypts `s_i_j` using an ephemeral ECDH key derived from peer `j`'s public key (from their certificate), then sends via `DKG_SHARE` (relayed through Coordinator, addressed by session handle).
3. Each node `j` decrypts and verifies each received share `s_i_j` against the commitment: `s_i_j * G == sum(C_i_k * j^k for k in 0..t-1)`. If verification fails, node broadcasts `DKG_ABORT`.

**Completion:**
1. Each node `i` computes its final share: `x_i = sum(s_j_i for all j in group)`.
2. Each node computes the group public key: `PK = sum(C_j_0 for all j in group)`.
3. All nodes must agree on `PK` (they broadcast their computed `PK`; Coordinator checks unanimity).
4. Coordinator records `PK` as the disposable key's public key and returns Key ID + public key to the client.

### 12.2 Abort Conditions

DKG is aborted if:
- Any node broadcasts `DKG_ABORT`.
- Fewer than `n` nodes complete Round 1 within the timeout.
- Computed `PK` values are not unanimous.
- The Coordinator's job TTL expires.

On abort, the Coordinator selects a new group and retries once. On second failure, the key creation request fails.

---

## 13. Threshold Signature Protocol (FROST)

### 13.1 Overview

Signing uses **FROST** (as per IETF draft-irtf-cfrg-frost-15 or latest). Only `t` of the `n` group nodes are needed to sign. The Coordinator selects `t` online nodes from the group.

### 13.2 Signer Selection

When a signing request arrives:
1. Coordinator looks up the group associated with the Key ID.
2. Filters group nodes to those currently `ONLINE`.
3. If fewer than `t` nodes are online: job fails immediately (returns error to client; see Section 24).
4. Otherwise: selects exactly `t` nodes (or more, at implementation's discretion, but FROST requires a fixed set to be declared before Round 1).
5. Broadcasts `JOB_ASSIGN` (signing) to the selected `t` nodes.

### 13.3 FROST Round 1 — Nonce Commitment

1. Each selected signer `i` generates a pair of random nonces `(d_i, e_i)` and computes commitments `(D_i, E_i) = (d_i * G, e_i * G)`.
2. Each signer sends `{D_i, E_i}` to the Coordinator.
3. The Coordinator assembles the **commitment list** `L = [(i, D_i, E_i) for all signers]` and broadcasts it to all signers.

### 13.4 FROST Round 2 — Partial Signatures

1. Each signer computes the **binding factor** `ρ_i = H(i, message, L)` per the FROST spec.
2. Each signer computes the group commitment `R = sum(D_i + ρ_i * E_i)`.
3. Each signer computes the challenge `c = H(R, PK, message)`.
4. Each signer computes its partial signature `z_i = d_i + e_i * ρ_i + λ_i * x_i * c` (where `λ_i` is the Lagrange coefficient for signer `i`, `x_i` is the signer's share).
5. Each signer sends `z_i` to the Coordinator.

### 13.5 Aggregation

1. Coordinator (or any party) verifies each partial signature `z_i` against the signer's share commitment.
2. Coordinator aggregates: `z = sum(z_i for all signers)`.
3. Final signature: `σ = (R, z)` — a standard Ed25519-compatible Schnorr signature.
4. Coordinator verifies `σ` against `PK` and the message before returning to client.

### 13.6 Nonce Security

- Nonces MUST be generated fresh for each signing operation (never reused).
- Signers MUST NOT pre-generate and store nonce batches before receiving a job assignment, to prevent state-compromise attacks.
- Nonces MUST be discarded immediately after use.

---

## 14. Key Share Storage and Reconstruction

### 14.1 Share Encryption at Rest

Each node stores key shares encrypted using the node's long-term storage key:
- Storage key: derived from the node's mTLS private key using HKDF-SHA-256 with info `"share-storage-v1"`.
- Encryption: AES-256-GCM.
- AAD: `key_id || node_id` (prevents shares being transplanted between nodes or keys).

### 14.2 Share Index

Each node maintains a local index:

```
key_id → { encrypted_share, threshold_params, group_public_key, account_id_hash }
```

The `account_id_hash` enables account-level enumeration of keys (e.g., for listing a user's disposable keys) without the node learning the full account ID.

### 14.3 Share Availability During Node Absence

If a node goes offline while holding shares for an active key:
- Signing requests are served by the remaining `t` nodes (if available).
- If fewer than `t` nodes are available, signing fails until enough nodes return.
- Shares are not redistributed automatically (this avoids complex re-sharing protocols). Instead, the system relies on `n > t` to provide redundancy.

### 14.4 Share Destruction

On key destruction (Section 18.4), the Coordinator broadcasts `KEY_DESTROY` to **all** group nodes (not just those currently online). Nodes acknowledge with `KEY_DESTROY_ACK`. Nodes that are offline at destruction time MUST wipe the share upon next reconnection, before being admitted to any new groups. Coordinator tracks outstanding `KEY_DESTROY_ACK` messages.

---

## 15. Public-Facing REST API

### 15.1 Base URL

```
https://<system-domain>/api/v1/
```

### 15.2 Content Negotiation

- All requests: `Content-Type: application/json`
- All responses: `Content-Type: application/json`
- Encoding: UTF-8 always.

### 15.3 Endpoints

#### POST /api/v1/keys

Create a new disposable key pair.

**Request body (RFC 8785 canonicalized, then signed):**

```json
{
  "envelope": {
    "version": "1",
    "action": "create_key",
    "nonce": "<16-byte random, base64url>",
    "timestamp": "<ISO 8601 UTC>",
    "sub_key_pub": "<base64url Ed25519 pub key>",
    "root_key_pub": "<base64url Ed25519 pub key>",
    "authorization": {
      "token": { ... },
      "token_sig": "<base64url>"
    },
    "params": {
      "threshold_t": 3,
      "threshold_n": 5
    }
  },
  "sig": "<base64url Ed25519 signature by sub key over canonical JSON of envelope>"
}
```

**Response 201:**
```json
{
  "key_id": "<UUID v4>",
  "public_key": "<base64url Ed25519 public key>",
  "threshold_t": 3,
  "threshold_n": 5,
  "created_at": "<ISO 8601>"
}
```

---

#### GET /api/v1/keys

List all active disposable keys associated with the caller's root key account.

**Request:** signed envelope in `X-MPC-Request` header (same structure, `action: "list_keys"`).

**Response 200:**
```json
{
  "keys": [
    {
      "key_id": "<UUID v4>",
      "public_key": "<base64url>",
      "threshold_t": 3,
      "threshold_n": 5,
      "created_at": "<ISO 8601>",
      "state": "ACTIVE"
    }
  ]
}
```

---

#### POST /api/v1/keys/`{`key_id`}`/sign

Sign a message using a specified disposable key.

**Request body:**
```json
{
  "envelope": {
    "version": "1",
    "action": "sign",
    "nonce": "<base64url>",
    "timestamp": "<ISO 8601 UTC>",
    "sub_key_pub": "<base64url>",
    "root_key_pub": "<base64url>",
    "authorization": { "token": { ... }, "token_sig": "<base64url>" },
    "message": "<base64url — the raw bytes to be signed>"
  },
  "sig": "<base64url>"
}
```

**Response 200:**
```json
{
  "key_id": "<UUID v4>",
  "signature": "<base64url Ed25519 signature over message>",
  "public_key": "<base64url — the disposable key public key>",
  "signed_at": "<ISO 8601>"
}
```

---

#### DELETE /api/v1/keys/\<key_id\>

Destroy a disposable key. Wipes all shares.

**Request:** signed envelope in `X-MPC-Request` header (`action: "destroy_key"`).

**Response 200:**
```json
{
  "key_id": "<UUID v4>",
  "destroyed_at": "<ISO 8601>",
  "ack_count": 4,
  "pending_ack_count": 1
}
```

Note: `pending_ack_count > 0` is informational; it indicates some nodes were offline and will wipe upon reconnection. The key is considered destroyed from the system's perspective immediately.

---

#### GET /api/v1/keys/\<key_id\>

Retrieve metadata for a single disposable key.

**Request:** signed envelope in `X-MPC-Request` header (`action: "get_key"`).

**Response 200:**
```json
{
  "key_id": "<UUID v4>",
  "public_key": "<base64url>",
  "threshold_t": 3,
  "threshold_n": 5,
  "created_at": "<ISO 8601>",
  "state": "ACTIVE | DESTROYING | DESTROYED"
}
```

---

### 15.4 Standard HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Resource created |
| 400 | Malformed request (not canonical JSON, missing fields, etc.) |
| 401 | Signature verification failed |
| 403 | Root key attempted to sign directly; sub key authorization invalid |
| 404 | Key ID not found or not owned by caller |
| 409 | Key is already in DESTROYING or DESTROYED state |
| 429 | Rate limit exceeded |
| 500 | Internal error |
| 503 | Insufficient online nodes to form a group or complete signing |

---

## 16. Request Authentication Model

### 16.1 Overview

Every API request (except health check) MUST carry a **signed request envelope**. The system is entirely **authentication-by-signature** — there are no sessions, API keys, or bearer tokens.

### 16.2 Request Envelope Construction

1. Construct the `envelope` JSON object with all required fields.
2. Serialize `envelope` using **RFC 8785 (JCS)** canonical JSON.
3. Sign the canonical bytes using the sub key's Ed25519 private key.
4. Encode the signature as base64url.
5. Construct the final request body: `{ "envelope": <envelope object>, "sig": "<base64url>" }`.

### 16.3 Verification Steps (Server Side)

The API Gateway performs the following checks **in order**, rejecting on first failure:

1. **Structure**: The body is valid JSON with `envelope` and `sig` fields.
2. **Canonical form**: Re-serialize `envelope` with JCS; it must match the received bytes (prevents signature mauling).
3. **Timestamp freshness**: `envelope.timestamp` must be within ±5 minutes of server time.
4. **Nonce uniqueness**: `envelope.nonce` must not have been seen in the last 10 minutes (short-lived nonce cache keyed by nonce + sub_key_pub).
5. **Authorization token structure**: `authorization.token` must be valid JSON with all required fields.
6. **Authorization token signature**: Verify `authorization.token_sig` using `root_key_pub` over the canonical token.
7. **Sub key binding**: `authorization.token.sub_key_pub` must equal `envelope.sub_key_pub`.
8. **Root key not a signer**: Check that `root_key_pub` is not itself a known sub key (and vice versa).
9. **Root key not direct signer**: The request signer (from `sig`) must be `sub_key_pub`, not `root_key_pub`.
10. **Request signature**: Verify `sig` using `sub_key_pub` over the canonical `envelope`.
11. **Account guard**: Verify that `root_key_pub` is not flagged as a direct-signer key (prevents step 9 bypass via account creation race).

### 16.4 Nonce and Replay Protection

- Nonces are 16 random bytes (base64url encoded = 22 characters).
- The Gateway maintains a nonce cache with TTL = 10 minutes.
- Combined with the 5-minute timestamp window, replay attacks are infeasible.

---

## 17. Account and Pseudo-Account Model

### 17.1 Account Identifier

The pseudo-account identifier is:

```
account_id = lowercase_hex(SHA-256(canonical_serialization(root_key_pub_bytes)))
```

This is a 64-character hex string. It is never the raw public key — hashing provides a stable identifier while minimizing the data retained.

### 17.2 Account Creation

Accounts are created **implicitly** on the first valid API request from a new root key. No explicit registration endpoint exists.

On first request:
1. Gateway verifies the request (Section 16.3).
2. Coordinator checks if `account_id` exists in the registry.
3. If not: Coordinator creates a new pseudo-account record: `{ account_id, first_seen_at }`.
4. **The root key public key itself is NOT stored.** Only its hash is retained.

### 17.3 Account Capabilities

An account can:
- Hold any number of active disposable keys.
- Be acted upon by any sub key that carries a valid Authorization Token from the corresponding root key.

### 17.4 Account Deletion

There is no explicit account deletion endpoint. When all disposable keys associated with an account have been destroyed, the account record is a bare identifier. Implementations MAY garbage-collect accounts with no active keys after a configurable retention period (recommended: 90 days).

---

## 18. Disposable Key Lifecycle

```
              ┌──────────┐
              │  CREATE  │  ──→  DKG protocol  ──→  ACTIVE
              └──────────┘
                                        │
                                        ├──→  SIGN (0 or more times)
                                        │
                                        ▼
                                    DESTROYING
                                        │
                              (all shares wiped)
                                        │
                                        ▼
                                    DESTROYED
```

### 18.1 Creation

Triggered by `POST /api/v1/keys`. The key transitions from `PENDING` (internal) to `ACTIVE` upon DKG completion. The public key is returned to the user.

### 18.2 Signing

Triggered by `POST /api/v1/keys/<key_id>/sign`. The key state remains `ACTIVE` after signing. A key can be signed with an unlimited number of times until destroyed.

### 18.3 Key Metadata Retained

For an active key, the system retains only:
- Key ID (UUID v4)
- Account ID hash
- Group node handles (session-scoped)
- Group public key (Ed25519 point)
- Threshold parameters `(t, n)`
- Creation timestamp
- State

No message content, signature history, or user-identifying data beyond the account hash is stored.

### 18.4 Destruction

Triggered by `DELETE /api/v1/keys/<key_id>`. On destruction:
1. Coordinator sets key state to `DESTROYING`.
2. Coordinator broadcasts `KEY_DESTROY` to all group nodes.
3. Each node wipes the share from storage and returns `KEY_DESTROY_ACK`.
4. Coordinator records destruction timestamp and marks key `DESTROYED`.
5. Key metadata is retained for audit purposes with state `DESTROYED` (no public key or group info required).

---

## 19. Anti-Collusion Mechanisms

### 19.1 VRF-Based Group Selection (Primary)

Described in Section 11.2. Prevents the Coordinator from biasing selection toward colluding nodes. The VRF proof is published in the audit log, making biased selection detectable after the fact.

### 19.2 Opaque Node Handles (Session Isolation)

During DKG and signing, nodes are addressed by ephemeral, session-scoped handles. These handles:
- Are random UUIDs assigned by the Coordinator per job.
- Do not appear in the audit log.
- Are destroyed after job completion.
- Prevent nodes from identifying each other across sessions.

### 19.3 Relayed Inter-Node Messages

All DKG and signing inter-node messages (`DKG_SHARE`, `SIGN_PARTIAL_SIG`, etc.) are **relayed through the Coordinator**. Nodes never establish direct connections with each other. This means:
- Nodes cannot discover each other's network identities.
- The Coordinator sees encrypted payloads but cannot decrypt them (share payloads are encrypted point-to-point between nodes).

### 19.4 Load-Based Assignment Caps

No node may be assigned to more groups than the configured maximum concurrency limit. This limits the blast radius of a compromised or colluding node.

### 19.5 Temporal Separation

Group assignments for consecutive requests from the same account are made with different VRF seeds, ensuring different group compositions where node pool size permits.

---

## 20. Observability and Uptime Tracking

### 20.1 Node Health Metrics

Each node reports a `HEALTH_REPORT` message to the Coordinator every 30 seconds:

```json
{
  "node_id": "<opaque>",
  "timestamp": "<ISO 8601>",
  "active_groups": 3,
  "pending_jobs": 1,
  "cpu_percent": 12.4,
  "memory_mb": 256,
  "share_count": 47,
  "error_count_1m": 0,
  "latency_p99_ms": 18
}
```

### 20.2 Uptime Tracking

The Coordinator maintains per-node uptime records:

| Metric | Description |
|--------|-------------|
| `last_seen` | Timestamp of last `PING` or message |
| `uptime_ratio_24h` | Fraction of last 24 hours node was ONLINE |
| `uptime_ratio_7d` | Fraction of last 7 days node was ONLINE |
| `consecutive_failures` | Current streak of missed heartbeats |
| `total_jobs_completed` | Lifetime count |
| `total_jobs_failed` | Lifetime count |

### 20.3 Coordinator Metrics Endpoint

The Coordinator exposes an internal (non-public) `/metrics` endpoint in Prometheus format:

```
mpc_nodes_online_total
mpc_nodes_degraded_total
mpc_nodes_offline_total
mpc_dkg_jobs_total{status="success|failure"}
mpc_sign_jobs_total{status="success|failure"}
mpc_job_duration_seconds{type="dkg|sign",quantile="0.5|0.95|0.99"}
mpc_active_keys_total
mpc_destroyed_keys_total
```

### 20.4 Audit Log

The Coordinator maintains an **append-only, signed audit log**. Each entry is:

```json
{
  "seq": 12345,
  "timestamp": "<ISO 8601>",
  "event_type": "<string>",
  "account_id": "<hex, if applicable>",
  "key_id": "<UUID, if applicable>",
  "details": { ... },
  "coordinator_sig": "<base64url signature over canonical JSON of all other fields>"
}
```

| Event Type | Logged When |
|-----------|-------------|
| `NODE_CONNECTED` | Node completes mTLS handshake |
| `NODE_DISCONNECTED` | Node goes offline |
| `NODE_REVOKED` | Node certificate revoked |
| `KEY_CREATED` | DKG completes successfully |
| `KEY_CREATION_FAILED` | DKG failed after all retries |
| `KEY_SIGNED` | Signing job completes |
| `KEY_SIGNING_FAILED` | Signing job failed |
| `KEY_DESTROYED` | All shares wiped |
| `GROUP_FORMED` | VRF selection published (seed + proof) |
| `ACCOUNT_CREATED` | New account_id first seen |

---

## 21. Fault Tolerance and Recovery

### 21.1 Signing with Fewer Than n Nodes

FROST requires only `t` nodes. If between `t` and `n-1` group nodes are online, signing proceeds normally. The Coordinator selects `t` of the available nodes.

If fewer than `t` group nodes are online, signing fails with error `INSUFFICIENT_NODES` (HTTP 503). The client should retry later.

### 21.2 Node Failure During DKG

If a node fails mid-DKG:
- The Coordinator detects absence (timeout or disconnection).
- The DKG job is marked `FAILED`.
- Coordinator selects a **fresh group** (new VRF seed, new node set) and retries the DKG once.
- On second failure, the key creation request fails with HTTP 503.

### 21.3 Node Failure During Signing

- If a selected signer drops after `JOB_ASSIGN` but before Round 1 completes: abort and retry with a different set of `t` nodes from the same group (if available).
- If fewer than `t` nodes remain: fail with HTTP 503.

### 21.4 Coordinator Failure

The Coordinator is a single point of operational failure (though not a security risk — it never holds key material). For high-availability deployments:
- Deploy the Coordinator behind a load balancer with at least two instances.
- Use a shared database for node registry, key metadata, and job queue.
- Nodes reconnect to any Coordinator instance on failover; mTLS certificates are verified the same way.
- In-flight jobs are lost on Coordinator failure and the client receives a timeout; the client should retry.

### 21.5 Offline Node Share Recovery

If a node goes permanently offline while holding shares for a key that still requires them for future signings, options are:
- **If n > t**: sufficient redundancy exists. The remaining nodes can continue signing.
- **If exactly t nodes remain**: the system is at threshold. Recommend key destruction and re-creation.
- **If fewer than t nodes remain**: the key is permanently inaccessible. This is a data loss scenario. The system SHOULD alert operators when any key drops below `t + 1` available nodes.

---

## 22. Data Minimisation and Privacy

The system is designed to retain the minimum data necessary for operation:

| Data Item | Retained? | Notes |
|-----------|-----------|-------|
| Root key public key | No | Hash (account_id) only |
| Sub key public key | No | Not stored after request verification |
| Authorization token | No | Verified in-flight; discarded |
| Message content | No | Never stored; signed and returned |
| Signature | No | Returned to caller; not retained |
| Disposable key public key | Yes (while ACTIVE) | Needed to return on `GET /keys` |
| Disposable key share | Yes (encrypted at rest) | Wiped on destruction |
| Account_id (hash) | Yes | Minimum identifier |
| Key creation/destruction timestamps | Yes | Audit log |
| Node identities | Yes | Required for operation; access-controlled |

The system explicitly avoids storing IP addresses, user-agent strings, or any metadata that could enable tracking of individual users beyond the account hash.

---

## 23. Message Formats and Schemas

### 23.1 RFC 8785 Canonicalization

All JSON objects that are signed MUST be serialized using RFC 8785 (JCS) before signing. Key requirements:
- Keys sorted lexicographically (Unicode code point order).
- No insignificant whitespace.
- Numbers serialized without trailing zeros.
- Strings escaped per JSON spec.

Libraries: `canonicalize` (Go), `json-canonicalize` (JS/TS), `jcs` (Python), `serde-jcs` (Rust).

### 23.2 Ed25519 Key Encoding

All Ed25519 public keys and signatures are encoded as **base64url without padding** (RFC 4648 §5, no `=` characters).

Raw byte lengths:
- Public key: 32 bytes → 43 base64url characters.
- Signature: 64 bytes → 86 base64url characters.

### 23.3 Timestamps

All timestamps: ISO 8601 format, UTC, to millisecond precision. Example: `2026-03-24T14:32:00.123Z`.

### 23.4 Error Response Format

```json
{
  "error": {
    "code": "INVALID_SIGNATURE",
    "message": "Request signature verification failed",
    "request_id": "<UUID v4>"
  }
}
```

---

## 24. Error Codes and Failure Semantics

| Code | HTTP | Meaning |
|------|------|---------|
| `INVALID_JSON` | 400 | Request body is not valid JSON |
| `NOT_CANONICAL` | 400 | Envelope JSON is not RFC 8785 canonical |
| `MISSING_FIELD` | 400 | Required envelope field absent |
| `EXPIRED_TIMESTAMP` | 401 | Timestamp outside ±5 minute window |
| `REPLAYED_NONCE` | 401 | Nonce has been seen before |
| `INVALID_SIGNATURE` | 401 | Request signature does not verify |
| `INVALID_AUTHORIZATION` | 401 | Authorization token signature does not verify |
| `SUB_KEY_MISMATCH` | 401 | Request signer does not match token sub_key_pub |
| `ROOT_KEY_SIGNING` | 403 | Request was signed by a root key |
| `KEY_NOT_FOUND` | 404 | Specified key_id does not exist or belongs to another account |
| `KEY_DESTROYED` | 409 | Key has already been destroyed |
| `KEY_BEING_DESTROYED` | 409 | Destruction is in progress |
| `INSUFFICIENT_NODES` | 503 | Not enough online nodes to complete operation |
| `DKG_FAILED` | 503 | Key generation failed after retries |
| `SIGNING_FAILED` | 503 | Threshold signing failed |
| `COORDINATOR_UNAVAILABLE` | 503 | Coordinator temporarily unreachable |
| `INTERNAL_ERROR` | 500 | Unexpected internal error |

---

## 25. Security Considerations

### 25.1 Private Key Never Assembled

The FROST/Pedersen DKG protocol mathematically guarantees that the disposable key's private scalar is never present in any single location. This is the fundamental security property of the system.

### 25.2 Root Key Isolation

The root key is an offline key. The system is designed so that the root key is **never required to interact with the network**. Its sole function is to issue Authorization Tokens offline. Even if the MPC system is fully compromised, an attacker gains no ability to extract the root key.

### 25.3 Sub Key Compromise

If a sub key is compromised:
- The attacker can make API requests until detected.
- The attacker cannot forge Authorization Tokens (those require the root key).
- Mitigation: the root key owner generates a new Authorization Token for a new sub key; the compromised sub key's tokens expire naturally (if `expires_at` is set) or the account is effectively abandoned.

### 25.4 Coordinator Compromise

The Coordinator is a **high-value target** because it controls group formation. However:
- Compromised Coordinator cannot obtain key material (it never holds shares or private keys).
- Compromised Coordinator could bias group selection (mitigated by VRF audit log) or deny service.
- Compromised Coordinator could trigger signing jobs for keys it doesn't own (mitigated: signing requests are authenticated by sub keys; the Coordinator cannot forge user requests).

### 25.5 Timing and Side Channels

Implementations MUST use **constant-time comparison** for all signature verification and share operations. Variable-time operations on secret data are a side-channel vulnerability.

### 25.6 Memory Safety

Implementations MUST securely zero memory holding key shares, nonces, and partial signatures after use. Languages with garbage collection require special handling (e.g., pinned memory buffers cleared before GC).

### 25.7 Certificate and PKI Security

Node certificate private keys MUST be stored in hardware security modules (HSMs) or TPMs where available. If software-only, keys must be encrypted at rest.

---

## 26. Implementation Guidance

### 26.1 Recommended Stack

**Coordinator and Node (backend):** Rust is the recommended implementation language. Rationale:
- Memory safety eliminates classes of side-channel and buffer-overflow vulnerabilities.
- Strong ecosystem for cryptography (`ed25519-dalek`, `frost-ed25519`, `rustls`).
- Excellent async networking via `tokio` with WebSocket support (`tokio-tungstenite`).
- Zero-cost abstractions for performance without GC pauses.

Alternative: Go. Advantages: simpler concurrency model, fast startup. Disadvantage: GC makes secure memory zeroing harder.

**API Gateway:** Any reverse proxy (nginx, Envoy) for TLS termination + a thin Rust/Go service for request validation.

**Coordinator Database:** PostgreSQL for the node registry, key metadata, and job queue. Redis for nonce cache (TTL-based).

**Audit Log:** Append-only log to a PostgreSQL table with Coordinator signatures, mirrored to an immutable object store (e.g., S3 with Object Lock) for tamper evidence.

### 26.2 FROST Library

Use the reference implementation from the `frost-ed25519` crate (Rust) or the Zcash Foundation's `frost-core`. These implement the full IETF draft and are under active security review.

### 26.3 WebSocket Library

- Rust: `tokio-tungstenite`
- The mTLS configuration MUST set `require_client_auth = true` on the Coordinator's TLS acceptor.
- Each WebSocket connection MUST be validated: certificate chain → CRL/OCSP → node registry lookup.

### 26.4 Key Storage

Shares MUST be stored encrypted. The encryption key derivation (Section 14.1) ties the share to the specific node, preventing offline transplantation attacks. Shares SHOULD be stored on a separate disk partition from the node binary and configuration.

### 26.5 Deployment Topology

```
Internet
    │
    └─→ Load Balancer (TLS termination for REST)
              │
              └─→ API Gateway (request validation, auth)
                        │
                        └─→ Coordinator (internal network, no public exposure)
                                  │ (mTLS WebSocket, internal network only)
                          ┌───────┴────────┐
                          │                │
                        Node 1 ... Node N (VPC / private network)
```

Nodes MUST NOT be publicly accessible. They connect **outbound** to the Coordinator. Firewall rules must enforce this.

---

## 27. Open Questions and Future Work

1. **Key refresh / proactive secret sharing**: Periodically re-randomize shares without changing the public key. Mitigates long-term share exposure. Not in scope for v1.

2. **Threshold re-configuration**: Changing `(t, n)` for an existing key after creation. Requires a full re-sharing protocol. Not in scope for v1.

3. **Multi-coordinator federation**: For geographically distributed deployments. Requires distributed job queue and consensus on group state.

4. **Authorization Token expiry handling**: The current spec allows optional `expires_at` in tokens. A mechanism for the user to revoke specific sub keys (without the root key) is not yet defined.

5. **Key export**: Exporting a private key share from the MPC system is explicitly out of scope and should not be implemented. The system is designed for keys that never exist in assembled form.

6. **Audit log external verification**: A mechanism for external parties to verify the integrity of the audit log (e.g., a Merkle tree published periodically) is recommended for high-assurance deployments.

---

*End of Specification — v1.0.0*