---
layout: default
title: "The EUDI Wallet Ecosystem: A Technical Deep Dive (Part 1)"
---

# The EUDI Wallet Ecosystem: A Technical Deep Dive

*Part 1 — Protocols, Credential Formats, and Verification*

The European Union is building a digital identity wallet for every citizen. Mandated by **eIDAS 2.0** (2024), every EU member state must offer a digital identity wallet — a smartphone app that lets citizens authenticate with online services, store and selectively share credentials, and sign documents electronically.

But how does it actually work under the hood? This post starts broad and progressively dives into the technical details of the protocols, credential formats, trust mechanisms, and verification flows that make up the EUDI ecosystem.

## The Big Picture

The EUDI wallet ecosystem has five key roles:

```
┌──────────────────────────────────────────────────────────────────┐
│                       Trust Anchor (TSL)                         │
│           Publishes trusted entity lists (ETSI TS 119 612)       │
└───────┬──────────────────┬───────────────────┬───────────────────┘
        │ trusts           │ trusts            │ trusts
        ▼                  ▼                   ▼
┌───────────────┐  ┌──────────────┐  ┌─────────────────────────────┐
│  Credential   │  │    Wallet    │  │  Verifier / Relying Party   │
│  Issuer       │  │   (Holder)   │  │  (e.g. online service)      │
└───────┬───────┘  └──┬───────┬───┘  └──────────┬──────────────────┘
        │  OID4VCI    │       │      OID4VP     │
        └─────────────┘       └─────────────────┘

┌───────────────────────┐  ┌───────────────────────────────────────┐
│ Attestation Provider  │  │ Status Provider                       │
│ Verifier Reg. Certs   │  │ Token Status Lists (revocation)       │
└───────────────────────┘  └───────────────────────────────────────┘
```

- **Trust Anchor** — A national authority that publishes signed trust lists. These lists declare which issuers and verifiers are legitimate.
- **Credential Issuer** — Issues digital credentials to the wallet (e.g., a government agency issuing a national ID). Uses the **OID4VCI** protocol.
- **Wallet (Holder)** — A smartphone app that stores credentials and presents them when requested. The citizen controls what gets shared.
- **Verifier / Relying Party** — An online service that requests credentials from the wallet to authenticate or verify a user. Uses the **OID4VP** protocol.
- **Attestation Provider** — Issues registration certificates to verifiers, proving they are authorized to request specific credentials.
- **Status Provider** — Hosts revocation lists so verifiers can check if a credential has been revoked or suspended.

Two core protocols power the ecosystem, both built on **OAuth 2.0**:

| Protocol | Purpose |
|----------|---------|
| **OpenID4VCI** (OpenID for Verifiable Credential Issuance) | Getting credentials INTO the wallet |
| **OpenID4VP** (OpenID for Verifiable Presentations) | Getting credentials OUT for verification |

## Credential Formats

The EUDI ecosystem supports two credential formats:

### SD-JWT (Selective Disclosure JWT) — RFC 9901

SD-JWT is JSON-based and extends standard JWTs with selective disclosure. Instead of revealing the entire credential, the holder can choose which claims to share.

An SD-JWT credential looks like this:

```
<issuer-signed-jwt>~<disclosure-1>~<disclosure-2>~...~<kb-jwt>
```

The components separated by `~`:
1. **Issuer-signed JWT** — Contains hashed references (`_sd` array) to the claims, signed by the issuer
2. **Disclosures** — Each is a base64url-encoded JSON array: `[salt, claim_name, claim_value]`
3. **KB-JWT** (Key Binding JWT) — Proves the presenter is the credential owner (added at presentation time)

The key insight: the issuer-signed JWT does not contain the actual claim values. It only contains SHA-256 hashes of the disclosures. When presenting, the wallet includes only the disclosures for claims the user consents to share. The verifier hashes each received disclosure and checks it against the `_sd` array — this proves the claim was part of the original credential without revealing anything else.

**Example disclosure:**
```
Encoded:   WyJfc0kiLCAiZ2l2ZW5fbmFtZSIsICJFcmlrYSJd
Decoded:   ["_sI", "given_name", "Erika"]
Digest:    base64url(SHA-256("WyJfc0ki..."))  →  "kL2g...9xYU"

Credential payload:
{ "_sd": ["H0wL...dGFi", "kL2g...9xYU"], "_sd_alg": "sha-256" }
```

The salt in each disclosure ensures that identical values produce different hashes, preventing cross-credential correlation.

### ISO mDOC (Mobile Document) — ISO 18013-5

mDOC is CBOR-based (binary encoding) and designed primarily for proximity communication (NFC/BLE), though it also works over the internet. It uses a different structure:

- **IssuerSigned** — Contains per-claim `IssuerSignedItem` entries grouped by namespace, plus a COSE signature over a Mobile Security Object (MSO) that contains digests of all items
- **DeviceSigned** — Added at presentation time, contains a COSE signature proving the presenter holds the device key

Selective disclosure works similarly in principle: the MSO contains per-element digests, and the wallet only includes the items the user approves. The verifier recomputes hashes from received items and checks them against the MSO.

| Aspect | SD-JWT | mDOC |
|--------|--------|------|
| Encoding | JSON/JWT (text) | CBOR (binary) |
| Selective disclosure | Per-claim hashed disclosures | Per-claim digests in MSO |
| Holder binding | KB-JWT signed with `cnf.jwk` | DeviceAuth signed with device key |
| Session binding | KB-JWT `aud` + `nonce` | SessionTranscript hash |
| Primary use | Online verification | Proximity + online |

## Phase 1: Credential Issuance (OID4VCI)

Before a wallet can present credentials, it needs to receive them. OID4VCI defines how an issuer pushes credentials into a wallet. The most common flow is the **Pre-Authorized Code Flow**, used when the user is already authenticated with the issuer (e.g., logged into a government portal):

```
     User              Issuer                    Wallet
      │                   │                        │
      │  1. Authenticate  │                        │
      │ ────────────────► │                        │
      │                   │                        │
      │  2. QR code with  │                        │
      │  credential offer │                        │
      │ ◄──────────────── │                        │
      │                   │                        │
      │  3. Scan QR ─────────────────────────────► │
      │                   │                        │
      │                   │  4. Token request      │
      │                   │     (pre-auth code)    │
      │                   │ ◄───────────────────── │
      │                   │                        │
      │                   │  5. Access token       │
      │                   │     + c_nonce          │
      │                   │ ─────────────────────► │
      │                   │                        │
      │                   │  6. Credential request │
      │                   │     + proof JWT        │
      │                   │ ◄───────────────────── │
      │                   │                        │
      │                   │  7. Signed credential  │
      │                   │ ─────────────────────► │
```

**Step by step:**

1. The user authenticates with the issuer (username/password, eID, etc.)
2. The issuer generates a **credential offer** — a URI with a pre-authorized code:
   ```
   openid-credential-offer://?credential_offer_uri=
     https://issuer.example/credential-offer/abc123
   ```
   The offer contains the issuer URL, which credential types are available, and a one-time pre-authorized code (valid for ~5 minutes).
3. The user scans the QR code with their wallet app.
4. The wallet exchanges the pre-authorized code for an **access token** and a **c_nonce** (credential nonce).
5. The wallet builds a **proof-of-possession JWT** — this proves the wallet controls the key that will be bound to the credential:
   ```json
   {
     "typ": "openid4vci-proof+jwt",
     "alg": "ES256",
     "jwk": { /* wallet's public key */ }
   }
   {
     "iss": "did:example:wallet",
     "aud": "https://issuer.example",
     "nonce": "<c_nonce from step 5>",
     "iat": 1704067200
   }
   ```
6. The wallet sends a credential request with the proof JWT.
7. The issuer verifies the proof, creates the credential embedding the wallet's public key (in `cnf.jwk` for SD-JWT), signs it, and returns it. The wallet stores the credential locally.

There's also an **Authorization Code Flow** (the wallet initiates the flow, the user authenticates at the issuer via OAuth 2.0 with PKCE), but the pre-authorized flow is the most commonly used in the EUDI ecosystem.

## Phase 2: Credential Verification (OID4VP)

This is where the real complexity lives. When an online service needs to verify a user's identity, OID4VP defines how it requests and receives credentials from the wallet.

### The Full Flow

```
  User/Browser          Verifier              Wallet
      │                    │                    │
      │  1. Click          │                    │
      │  "Login with       │                    │
      │   Wallet"          │                    │
      │ ─────────────────► │                    │
      │                    │                    │
      │  2. openid4vp://   │                    │
      │  ?request_uri=...  │                    │
      │ ◄───────────────── │                    │
      │                    │                    │
      │  3. Open wallet ──────────────────────► │
      │                    │                    │
      │                    │  4. Fetch request  │
      │                    │ ◄───────────────── │
      │                    │                    │
      │                    │  5. Signed request │
      │                    │     object (JWT)   │
      │                    │ ─────────────────► │
      │                    │                    │
      │                    │         6. Verify  │
      │                    │         signature, │
      │                    │         show       │
      │                    │         consent UI │
      │                    │                    │
      │                    │  7. Encrypted      │
      │                    │     response (JWE) │
      │                    │ ◄───────────────── │
      │                    │                    │
      │                    │  8. Decrypt &      │
      │                    │     verify         │
      │                    │                    │
      │  9. Login success  │                    │
      │ ◄───────────────── │                    │
```

This uses **pass by reference**: the initial redirect only contains a short `request_uri` pointing to the full request object. The wallet fetches the actual request from that URI. This keeps QR codes small and redirect URLs manageable, since request objects can be large (DCQL query, encryption keys, registration certificate, etc.).

### Step 1: Requesting Credentials with DCQL

The verifier specifies what it needs using **DCQL (Digital Credentials Query Language)** — a JSON query language that replaces the older `presentation_definition` format:

```json
{
  "credentials": [{
    "id": "pid_credential",
    "format": "dc+sd-jwt",
    "meta": { "vct_values": ["eu.europa.ec.eudi.pid.1"] },
    "claims": [
      { "path": ["family_name"] },
      { "path": ["given_name"] },
      { "path": ["birthdate"] }
    ]
  }]
}
```

This query says: "I need a PID credential in SD-JWT format, and I only need the family name, given name, and birthdate." The wallet will only disclose these three claims — everything else in the credential stays hidden.

DCQL also supports **`credential_sets`** for expressing alternatives:

```json
{
  "credentials": [
    { "id": "german_pid", "format": "dc+sd-jwt", ... },
    { "id": "french_pid", "format": "dc+sd-jwt", ... }
  ],
  "credential_sets": [{
    "purpose": "Identity verification",
    "options": [["german_pid"], ["french_pid"]]
  }]
}
```

This says "I accept either a German PID or a French PID." The wallet picks whichever it has.

### Step 2: Verifier Authentication

The wallet needs to know who is requesting credentials. Four **client identifier schemes** exist:

| Scheme | `client_id` format | How trust is established |
|--------|-------------------|--------------------------|
| Pre-registered | `https://example.com` | Pre-registered with wallet provider |
| `x509_san_dns` | `x509_san_dns:example.com` | X.509 certificate with matching DNS SAN |
| `x509_hash` | `x509_hash:<sha256>` | SHA-256 fingerprint of X.509 certificate |
| `verifier_attestation` | `verifier_attestation:<sub>` | Attestation JWT from a trusted authority |

For `x509_san_dns` (the most common production scheme), the verifier signs the request JWT with its X.509 certificate (included in the `x5c` header). The wallet extracts the DNS Subject Alternative Name from the certificate and verifies it matches the `client_id`.

#### Registration Certificates

In the EUDI ecosystem, wallets additionally require a **Registration Certificate** (`rc-rp+jwt`) — issued by a national Trust Anchor — that explicitly lists which credentials and claims the verifier is authorized to request:

```json
{
  "typ": "rc-rp+jwt",
  "sub": "https://verifier.example.com",
  "service": "Identity Verification Service",
  "privacy_policy": "https://verifier.example.com/privacy",
  "credentials": [{
    "format": "dc+sd-jwt",
    "vct": "eu.europa.ec.eudi.pid.1",
    "claims": ["given_name", "family_name", "birthdate"]
  }]
}
```

The wallet enforces this: if a verifier requests claims not listed in its registration certificate, the request is rejected. This is a powerful privacy safeguard — a verifier that's only authorized for age verification can't suddenly request your full name and address.

### Step 3: Secure Response Delivery

HAIP (High Assurance Interoperability Profile) mandates that responses are **encrypted**. The verifier generates a fresh **ephemeral EC P-256 key pair** for each request and includes the public key in `client_metadata.jwks`. The wallet encrypts its response using ECDH-ES key agreement with A256GCM content encryption, producing a JWE (JSON Web Encryption).

```
Verifier                                  Wallet
   │                                        │
   │  Generate ephemeral P-256 key pair     │
   │  Include public key in request         │
   │ ─────────────────────────────────────► │
   │                                        │
   │              Encrypt vp_token with     │
   │              ECDH-ES + A256GCM         │
   │ ◄───────────────────────────────────── │
   │                                        │
   │  Decrypt with stored private key       │
```

A fresh key per request provides **forward secrecy** — compromising one key only affects that single session.

The response mode is `direct_post.jwt`: the wallet POSTs the encrypted JWE directly to the verifier's `response_uri`.

### Step 4: Credential Verification

Once the verifier decrypts the response, it must verify the credential's authenticity, integrity, and binding. This is the most involved step.

#### Trust Verification via ETSI Trust Lists

How does the verifier know the credential was issued by a legitimate authority?

1. **Fetch** the trust list (a signed JWT) from the Trust Anchor's URL
2. **Look up** the credential's issuer in the trust list
3. **Extract** the issuer's X.509 certificate from the trust list entry
4. **Verify** the credential's signature using that certificate

```json
{
  "trusted_entities": [{
    "entity_id": "https://pid-issuer.bundesdruckerei.de",
    "entity_name": "Bundesdruckerei PID Issuer",
    "trust_services": [{
      "type": "pid-issuance",
      "status": "granted",
      "x5c": ["MIIBjTCCATOgAwIBAgIUQ8..."]
    }]
  }]
}
```

Only the Trust Anchor's root certificate needs to be pre-configured — everything else is discovered dynamically.

#### SD-JWT Verification

For an SD-JWT credential, the verifier performs these checks:

1. **Parse** — Split on `~` to get: issuer JWT, disclosures[], KB-JWT
2. **Verify issuer signature** — Look up the issuer's public key via the trust list, verify the JWT signature
3. **Check timestamps** — `iat` must be in the past, `exp` must be in the future
4. **Verify disclosures** — For each disclosure:
   - Decode from base64url: `[salt, claim_name, claim_value]`
   - Compute `base64url(SHA-256(disclosure_string))`
   - Check the computed digest exists in the credential's `_sd` array
   - Reject duplicate digests or reserved claim names (`_sd`, `...`)
5. **Verify holder binding (KB-JWT)** — This proves the presenter owns the credential:
   - Extract `cnf.jwk` (the holder's public key) from the issuer-signed credential
   - Verify the KB-JWT signature with that public key
   - Check `aud` matches the verifier's `client_id`
   - Check `nonce` matches the request nonce
   - Check `iat` is recent (within acceptable time window)
   - Check `sd_hash` equals `base64url(SHA-256(<entire-presentation-string>))`

The `sd_hash` is particularly important: it binds the KB-JWT to the exact set of disclosed claims. Without it, an attacker could take a valid KB-JWT and attach it to a different set of disclosures.

#### mDOC Verification

For mDOC credentials, the process is analogous but uses CBOR/COSE instead of JSON/JWT:

1. **Parse CBOR** structure, extract Documents
2. **Verify COSE signature** (IssuerAuth) using the issuer's key from the trust list
3. **Validate MSO** (Mobile Security Object) — check docType, validity timestamps
4. **Verify IssuerSignedItems** — encode each to tagged CBOR, compute SHA-256, check against MSO's ValueDigests
5. **Verify DeviceAuth** — COSE signature with the device key embedded in the MSO, validating the SessionTranscript (which includes nonce, client_id, response_uri)

#### Revocation Checking with Token Status Lists

Credentials can be revoked or suspended. The issuer publishes a **Token Status List** (`statuslist+jwt`) — a DEFLATE-compressed bit array distributed as a signed JWT.

Each credential contains a status reference:
```json
{ "status_list": { "idx": 42, "uri": "https://issuer.example/status/1" } }
```

The verifier fetches the entire list, decompresses it, and reads the bits at index 42:

| Bits per entry | Possible statuses |
|---------------|-------------------|
| 1 bit | VALID / INVALID |
| 2 bits | VALID / INVALID / SUSPENDED |
| 8 bits | Up to 256 application-specific statuses |

This is **privacy-preserving by design**: the verifier fetches the entire list, so the issuer cannot determine which specific credential is being checked.

## HAIP: The Interoperability Profile

The OID4VP spec is intentionally flexible — too flexible for a real cross-border ecosystem. HAIP (High Assurance Interoperability Profile) narrows the choices to ensure EU-wide interoperability:

| Area | HAIP Requirement |
|------|-----------------|
| Signatures | ES256 (ECDSA with P-256) only |
| Response mode | `direct_post.jwt` or `dc_api.jwt` (always encrypted) |
| Encryption | ECDH-ES with P-256, A128GCM or A256GCM |
| Credential formats | SD-JWT VC (`dc+sd-jwt`) and mDOC |
| Query language | DCQL |

Without HAIP, two EU member states could implement OID4VP with completely different algorithms and formats, making cross-border interoperability impossible. HAIP is the "this is how we all agree to do it" profile.

## Holder Binding and Request Binding

Every credential presentation must prove two things:

**Holder binding** — The person presenting the credential is the person it was issued to.
- In SD-JWT: the issuer embeds the holder's public key in the credential (`cnf.jwk`). At presentation, the wallet signs a KB-JWT with the corresponding private key.
- In mDOC: the issuer embeds a `deviceKey` in the MSO. At presentation, the wallet signs a DeviceAuth structure with the device's private key.

**Request binding** — The response is tied to a specific verifier request, preventing replay attacks.
- In SD-JWT: the KB-JWT contains `aud` (verifier identity), `nonce` (from the request), and `sd_hash` (binds to the exact credential + disclosed claims).
- In mDOC: a SessionTranscript structure — deterministically computed from `nonce`, `client_id`, and `response_uri` — is included in the DeviceAuth signature. Both wallet and verifier compute it independently.

SD-JWT elegantly combines both in a single KB-JWT. mDOC separates them into DeviceAuth (holder) and SessionTranscript (request).

## Delivery Channels: How the Wallet Gets Involved

Three mechanisms exist to trigger the wallet from a browser:

### 1. W3C Digital Credentials API (DC API)

The newest and cleanest approach — a browser-native API similar to WebAuthn:

```javascript
const credential = await navigator.credentials.get({
  digital: {
    requests: [{
      protocol: "openid4vp-v1-signed",
      data: { request: requestObjectJwt }
    }]
  }
});
```

The browser mediates wallet selection natively. No redirects, no QR codes. However, browser support is still limited:

| Browser | Support |
|---------|---------|
| Chrome 141+ (Sept 2025) | `openid4vp-v1-signed` and `unsigned` |
| Safari 26+ (Sept 2025) | `org-iso-mdoc` only — no OpenID4VP |
| Firefox | Negative standards position |

The Safari limitation is significant: it only supports the ISO mDOC protocol through the DC API, not OpenID4VP. Implementers must handle both protocols for cross-browser compatibility.

### 2. Same-Device Redirect

On mobile, the browser redirects to the wallet app using a custom URI scheme:

```
openid4vp://?client_id=x509_san_dns:example.com
  &request_uri=https://example.com/request/abc123
```

The wallet app intercepts this URI, fetches the full request, shows the consent UI, and POSTs the response back.

### 3. Cross-Device QR Code

On desktop, the same `openid4vp://` URI is encoded as a QR code. The user scans it with their phone's wallet app, which completes the flow. The verifier polls or uses a callback to detect when the response arrives.

## Summary

The EUDI wallet ecosystem is a comprehensive system built on well-established standards:

- **eIDAS 2.0** provides the legal mandate
- **OID4VCI** handles credential issuance (built on OAuth 2.0)
- **OID4VP** handles credential verification (built on OAuth 2.0)
- **SD-JWT** and **mDOC** provide selective disclosure credentials
- **DCQL** specifies what claims are requested
- **ETSI Trust Lists** establish issuer trust
- **Token Status Lists** handle revocation
- **HAIP** ensures EU-wide interoperability
- **Registration Certificates** control what verifiers can request

The system is designed with privacy at its core: selective disclosure means services only see what they need, encrypted responses prevent eavesdropping, ephemeral keys provide forward secrecy, and status list design prevents issuer tracking.

---

## Coming Up: Part 2 — Integrating EUDI Wallet with Keycloak

Understanding the protocols is one thing — integrating them into a real identity and access management system is another. In Part 2, we'll show how we built a full OID4VP verifier as a Keycloak Identity Provider, turning wallet authentication into a first-class login method alongside Google, GitHub, or SAML.

We'll cover:

- **Why Keycloak is a natural fit** — OID4VP maps cleanly onto Keycloak's Identity Provider SPI, mapper infrastructure, and session management
- **Three authentication flows** — DC API, same-device redirect, and cross-device QR code, all configurable per IdP instance
- **Auto-generating DCQL from mappers** — Admins configure claim mappers in the Admin UI, the system builds the query automatically
- **The German PID problem** — How we solved user authentication when the national ID has no unique identifier, using supplementary credentials and DCQL `credential_sets`
- **Real-world deployment** — Testing against the German EUDI Wallet Sandbox and OIDF conformance suite

Stay tuned.
