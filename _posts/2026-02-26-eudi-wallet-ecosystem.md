---
layout: default
title: "The EUDI Wallet Ecosystem: A Technical Overview (Part 1)"
date: 2026-02-26
---

# The EUDI Wallet Ecosystem: A Technical Overview

*Part 1 - Protocols, Credential Formats, and Verification*

> **Note (March 20, 2026):** The section on trust lists and issuer verification was expanded in this version of the post.

The EU is building a digital identity wallet for every citizen. **eIDAS 2.0** (2024) requires every member state to offer one: a smartphone app that lets people log in to online services, store credentials, and share only the data they choose to.

This post explains how the whole thing works, starting with the big picture and then going deeper into the protocols, credential formats, and verification steps.

## The Big Picture

The ecosystem has five main roles:

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
│ Attestation Providers │  │ Status Provider                       │
│ (Registrars, Wallet   │  │ Token Status Lists (revocation)       │
│  Provider, Access CA) │  │                                       │
└───────────────────────┘  └───────────────────────────────────────┘
```

- **Trust Anchor:** A national authority that publishes signed lists of who's allowed to issue credentials and who's allowed to verify them.
- **Credential Issuer:** Puts credentials into the wallet (e.g., a government agency issuing a digital ID). Uses the **OID4VCI** protocol.
- **Wallet (Holder):** The citizen's phone app. Stores credentials and lets the user decide what to share with whom.
- **Verifier / Relying Party:** An online service that asks the wallet for credentials (e.g., to verify someone's age or identity). Uses **OID4VP**.
- **Attestation Providers:** Various entities that issue attestations to ecosystem participants. For example, an RP Registrar issues registration certificates to verifiers, a Wallet Provider issues wallet instance attestations proving the app's integrity, and Access CAs issue certificates to issuers and verifiers.
- **Status Provider:** Hosts revocation lists so verifiers can check if a credential has been revoked.

Two core protocols power everything. Both are built on **OAuth 2.0**:

| Protocol | What it does |
|----------|-------------|
| **OpenID4VCI** (Verifiable Credential Issuance) | Gets credentials INTO the wallet |
| **OpenID4VP** (Verifiable Presentations) | Gets credentials OUT for verification |

## Credential Formats

The ecosystem supports two formats:

### SD-JWT (Selective Disclosure JWT) - RFC 9901

SD-JWT extends regular JWTs with selective disclosure. Instead of sharing the whole credential, the holder picks which fields to reveal.

The format looks like this:

```
<issuer-signed-jwt>~<disclosure-1>~<disclosure-2>~...~<kb-jwt>
```

The parts, separated by `~`:
1. **Issuer-signed JWT:** Signed by the issuer, but instead of containing the actual values, it holds SHA-256 hashes of them (in an `_sd` array)
2. **Disclosures:** Each one is a base64url-encoded array: `[salt, claim_name, claim_value]`
3. **KB-JWT** (Key Binding JWT): Added when presenting, proves the person showing the credential is its rightful owner

The clever part: the signed JWT only has hashes, not actual values. When presenting, the wallet includes only the disclosures for claims the user agreed to share. The verifier hashes each disclosure and checks it against the `_sd` array, proving the claim was in the original credential without seeing anything else.

**Example:**
```
Encoded:   WyJfc0kiLCAiZ2l2ZW5fbmFtZSIsICJFcmlrYSJd
Decoded:   ["_sI", "given_name", "Erika"]
Digest:    base64url(SHA-256("WyJfc0ki..."))  →  "kL2g...9xYU"

Credential payload:
{ "_sd": ["H0wL...dGFi", "kL2g...9xYU"], "_sd_alg": "sha-256" }
```

The random salt in each disclosure makes sure that the same value (like "Erika") produces a different hash every time. This prevents anyone from guessing or correlating values across credentials.

If you want to inspect SD-JWTs and mdocs locally, [oid4vc-dev](https://github.com/dominikschlosser/oid4vc-dev) lets you decode and verify both formats.

### ISO mdoc (Mobile Document) - ISO 18013-5

mdoc uses CBOR (a compact binary format) instead of JSON. It was originally designed for proximity use cases like NFC and Bluetooth (think: showing your driving license at a checkpoint), but also works over the internet.

The structure is different from SD-JWT but the idea is the same:

- **IssuerSigned:** Contains individual claim items grouped by namespace, plus a COSE signature over a Mobile Security Object (MSO) with digests of all items
- **DeviceSigned:** Added at presentation time, proves the presenter holds the device key

Selective disclosure works the same way in principle: the MSO has a hash for each claim, and the wallet only reveals the items the user approves.

| Aspect | SD-JWT | mdoc |
|--------|--------|------|
| Encoding | JSON/JWT (text) | CBOR (binary) |
| Selective disclosure | Hashed disclosures | Digests in MSO |
| Primary use | Online verification | Proximity + online |

### Holder Binding and Request Binding

When someone presents a credential, the verifier needs to know two things: **Is this person the rightful owner?** and **Is this response meant for my request?** Both formats solve this, but differently.

**Holder binding** proves the presenter owns the credential. During issuance, the issuer embeds the holder's public key into the credential. During presentation, the wallet signs a proof with the matching private key. In SD-JWT, this key lives in the `cnf.jwk` claim and the proof is a **KB-JWT** (Key Binding JWT). In mdoc, the key is in the MSO's `deviceKey` field and the proof is a **DeviceAuth** COSE signature.

**Request binding** ties the response to a specific verifier request, preventing replay attacks. In SD-JWT, the KB-JWT includes `aud` (who asked), `nonce` (unique to this request), and `sd_hash` (a hash over the exact claims being shared). In mdoc, a **SessionTranscript** (built from `nonce`, `client_id`, and `response_uri`) is signed into DeviceAuth. Both sides compute it independently, no shared secret needed.

SD-JWT combines both in a single KB-JWT. mdoc also uses a single holder signature: DeviceAuth signs a payload that contains the SessionTranscript, so the request binding is an input to that signature rather than a separate proof.

## Credential Issuance (OID4VCI)

Before the wallet can show credentials, it needs to get them. OID4VCI defines how issuers deliver credentials to wallets. The most common variant is the **Pre-Authorized Code Flow**, used when the user is already logged in at the issuer (e.g., a government portal):

```
     User              Issuer                    Wallet
      │                   │                        │
      │  1. Log in        │                        │
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

**What happens:**

1. The user logs in to the issuer.
2. The issuer creates a **credential offer**, a URI containing a one-time code (valid for ~5 minutes):
   ```
   openid-credential-offer://?credential_offer_uri=
     https://issuer.example/credential-offer/abc123
   ```
3. The user scans the QR code with their wallet.
4. The wallet sends the code to the issuer and gets back an **access token** and a **c_nonce** (a fresh random value).
5. The wallet creates a **proof JWT** that proves it controls a specific key pair. The nonce from step 4 goes into this proof to prevent replay:
   ```json
   {
     "typ": "openid4vci-proof+jwt",
     "alg": "ES256",
     "jwk": { /* wallet's public key */ }
   }
   {
     "aud": "https://issuer.example",
     "nonce": "<c_nonce from step 4>",
     "iat": 1704067200
   }
   ```
6. The wallet sends a credential request with the proof.
7. The issuer checks the proof, creates the credential (embedding the wallet's public key so the credential is bound to this wallet), signs it, and sends it back. The wallet stores it locally.

There's also an **Authorization Code Flow** where the wallet initiates the process: it discovers the issuer's metadata, starts an OAuth 2.0 authorization request with PKCE, and exchanges the resulting authorization code for an access token. How the user authenticates during this flow depends on the issuer. In the German ecosystem, the wallet reads the user's physical eID card directly (via NFC) and handles the authentication itself, rather than redirecting to the PID provider's login page.

## Credential Verification (OID4VP)

This is where most of the complexity lives. When a service wants to verify someone's identity, OID4VP defines how it asks the wallet for credentials and how the wallet responds.

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

Notice the **pass by reference** pattern: the initial redirect only has a short `request_uri` pointing to the full request. The wallet fetches it from there. This keeps QR codes small, since the full request can be large (query, encryption keys, registration certificate, etc.).

### Requesting Credentials with DCQL

The verifier describes what it needs using **DCQL (Digital Credentials Query Language)**, a JSON format that specifies which credentials and which claims:

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

This says: "I need a PID credential in SD-JWT format, specifically the family name, given name, and birthdate." The wallet only reveals those three fields, nothing else.

DCQL also supports **`credential_sets`** for offering alternatives. For example, accepting a PID in either SD-JWT or mdoc format:

```json
{
  "credentials": [
    {
      "id": "pid_sdjwt",
      "format": "dc+sd-jwt",
      "meta": { "vct_values": ["eu.europa.ec.eudi.pid.1"] },
      "claims": [
        { "path": ["family_name"] },
        { "path": ["given_name"] }
      ]
    },
    {
      "id": "pid_mdoc",
      "format": "mso_mdoc",
      "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" },
      "claims": [
        { "path": ["eu.europa.ec.eudi.pid.1", "family_name"] },
        { "path": ["eu.europa.ec.eudi.pid.1", "given_name"] }
      ]
    }
  ],
  "credential_sets": [{
    "purpose": "Identity verification",
    "options": [["pid_sdjwt"], ["pid_mdoc"]]
  }]
}
```

The wallet picks whichever format it has.

Individual claims can also be marked as optional using **`claim_sets`**. By default, all listed claims are required, meaning the wallet must disclose them or the query fails. With `claim_sets`, you can define groups of claims where some are mandatory and others are nice-to-have:

```json
{
  "credentials": [{
    "id": "pid",
    "format": "dc+sd-jwt",
    "meta": { "vct_values": ["eu.europa.ec.eudi.pid.1"] },
    "claims": [
      { "id": "0", "path": ["family_name"] },
      { "id": "1", "path": ["given_name"] },
      { "id": "2", "path": ["birthdate"] },
      { "id": "3", "path": ["address"] }
    ],
    "claim_sets": [
      ["0", "1", "2", "3"],
      ["0", "1", "2"]
    ]
  }]
}
```

This says: "I need family name, given name, and birthdate. I'd also like the address, but it's not required." The wallet tries to satisfy the first `claim_set` (all four claims), but can fall back to the second (without address) if it's not available or the user declines to share it.

### Verifier Authentication

The wallet needs to know who's asking. Four **client identifier schemes** tell the wallet how to verify the verifier:

| Scheme | `client_id` example | Trust basis |
|--------|-------------------|-------------|
| Pre-registered | `https://example.com` | Pre-registered with wallet provider |
| `x509_san_dns` | `x509_san_dns:example.com` | X.509 cert with matching DNS name |
| `x509_hash` | `x509_hash:<sha256>` | SHA-256 hash of X.509 certificate |
| `verifier_attestation` | `verifier_attestation:<sub>` | Attestation JWT from trusted authority |

For `x509_san_dns`, the verifier signs its request with an X.509 certificate, and the wallet checks that the certificate's DNS name matches the `client_id`. For `x509_hash`, the wallet matches against the certificate's SHA-256 fingerprint instead. HAIP mandates support for both X.509-based schemes.

#### Registration Certificates

In the EUDI ecosystem, verifier authorization data can be conveyed either in a **Registration Certificate** (`rc-rp+jwt`) or directly by the Registrar. When a registration certificate is used, it explicitly lists what credentials and claims the verifier is allowed to ask for:

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

The verifier can include this certificate in the authorization request object via the `verifier_info` parameter. The wallet needs the same underlying authorization data even when no certificate is carried in the request: it can obtain it from the Registrar instead. In either case, if a verifier asks for claims outside its registered scope, the request gets rejected. A verifier that's only approved for age verification can't sneakily request your full name and address.

### Secure Response Delivery

HAIP (the EU's interoperability profile, more on that below) requires all responses to be **encrypted**. For each request, the verifier creates a fresh **ephemeral key pair** and sends the public key along. The wallet encrypts its response with that key:

```
Verifier                                  Wallet
   │                                        │
   │  Generate fresh P-256 key pair         │
   │  Send public key in request            │
   │ ─────────────────────────────────────► │
   │                                        │
   │              Encrypt response with     │
   │              ECDH-ES + A256GCM         │
   │ ◄───────────────────────────────────── │
   │                                        │
   │  Decrypt with stored private key       │
```

A new key for every request means **forward secrecy**: if one key leaks, only that one session is affected.

The wallet POSTs the encrypted response directly to the verifier's `response_uri` (this is called `direct_post.jwt` mode).

### Credential Verification

After decrypting the response, the verifier needs to check that the credential is real, unmodified, and presented by its rightful owner. This is the most involved part.

#### Checking Issuer Trust and Authorization via ETSI Trust Lists

How does the verifier know the credential came from a legitimate issuer?

1. **Fetch** the signed trust list published by the Trust Anchor
2. **Find** the credential's issuer or provider entry in the list
3. **Check** that the relevant trust service has the right service type and appears in the relevant EUDI trust list
4. **Check** that the trust service, or associated registration data, covers the specific attestation type being verified
5. **Check** that the credential's signing certificate or key material chains to that trusted service information
6. **Verify** the credential's signature

```json
{
  "ListAndSchemeInformation": {
    "LoTEType": "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
    "ListIssueDateTime": "2026-03-21T23:04:36.430Z",
    "NextUpdate": "2026-03-22T23:04:36.430Z",
    "SchemeOperatorName": [{ "lang": "de-DE", "value": "SPRIND GmbH" }]
  },
  "TrustedEntitiesList": [{
    "TrustedEntityInformation": {
      "TEName": [{ "lang": "de-DE", "value": "Bundesdruckerei GmbH" }],
      "TEInformationURI": [{ "lang": "de-DE", "uriValue": "https://www.bdr.de" }]
    },
    "TrustedEntityServices": [{
      "ServiceInformation": {
        "ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/PID/Issuance",
        "ServiceName": [{ "lang": "de-DE", "value": "PID-Ausstellungsdienst der Bundesdruckerei" }],
        "ServiceDigitalIdentity": {
          "X509Certificates": [{ "val": "MIICPTCCAeKgAwIBAgIUeQcP5UXW68vbf5vr25j+JfnBz0Ew..." }]
        }
      }
    }]
  }]
}
```

The example above is an excerpt from a PID Providers List JWT. For this specific case, the authorization signal is the service type itself: a verifier checking a PID must find a trusted service with `ServiceTypeIdentifier = .../PID/Issuance`. ETSI TS 119 602's PID Providers List profile does **not** use a `ServiceStatus` field: listed PID services are approved by virtue of being present in the list, and services that are no longer approved are removed from the list. Operationally, a verifier fetches and revalidates the list using normal HTTP caching headers such as `Cache-Control`, `ETag`, or `Last-Modified`, while also treating `NextUpdate` as the LoTE's expiry bound.

More generally, the split is:

- the trust list tells the verifier whether this provider and trust service are trusted in the EUDI ecosystem
- the service type, and in some ecosystems additional registration data, tells the verifier what this provider is actually allowed to issue
- the credential's signature proves that this exact credential came from a key belonging to that trusted provider

That last point matters. A valid signature alone is not enough. It only proves that some private key signed the credential. The verifier also has to establish that the key belongs to a provider that is both trusted and entitled to issue this kind of credential.

For SD-JWT VC in general, issuer keys can be distributed through JWT VC Issuer Metadata at `/.well-known/jwt-vc-issuer`, with either embedded `jwks` or a `jwks_uri`, or through an X.509 certificate chain in the credential header. In the EUDI/HAIP 1.0 profile, issuer signature validation uses the X.509 `x5c` chain from the credential header. The verifier must check issuer authorization independently; the `vct` value itself does **not** authorize the issuer.

Only the Trust Anchor's own certificate needs to be pre-configured. Everything else is looked up dynamically.

**Concrete example**

Suppose the verifier receives this SD-JWT VC:

```json
{
  "header": {
    "alg": "ES256",
    "typ": "dc+sd-jwt",
    "x5c": ["leaf-cert", "issuer-intermediate-cert"]
  },
  "payload": {
    "vct": "eu.europa.ec.eudi.pid.1"
  }
}
```

The verifier then checks:

1. the list type is `http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList`, so this is the right trust list for PID issuers
2. there is a matching trusted service with `ServiceTypeIdentifier = http://uri.etsi.org/19602/SvcType/PID/Issuance`
3. the cached list is usable: HTTP cache-control or revalidation rules have been applied, and `NextUpdate` is not in the past
4. that service entry is listed under the `Bundesdruckerei GmbH` trusted-entity entry
5. the certificate chain from the credential header links back to the `X509Certificates` material for that PID issuance service
6. because the credential's `vct` is `eu.europa.ec.eudi.pid.1`, the `.../PID/Issuance` service type is the relevant authorization check
7. the SD-JWT signature verifies with the public key from the end-entity certificate

If the signature verifies but the service type, trust-list freshness, or certificate-chain linkage checks fail, the verifier rejects the credential. A technically valid signature is not enough if the certificate chain does not lead back to a trusted PID issuance service in the PID Providers List used for verification.

#### SD-JWT Verification

For an SD-JWT credential, the verifier runs through these checks:

1. **Parse:** Split on `~` to get the issuer JWT, disclosures, and KB-JWT
2. **Resolve and check the issuer signature:** Read the SD-JWT header's `x5c`, validate the certificate chain against the trusted service information, confirm that the matching trusted service category covers the credential's attestation type, and verify the JWT signature with the end-entity certificate's public key
3. **Check timestamps:** `iat` (issued at) in the past, `exp` (expires) in the future
4. **Check each disclosure**:
   - Decode it: `[salt, claim_name, claim_value]`
   - Hash it: `base64url(SHA-256(disclosure_string))`
   - Make sure the hash is in the credential's `_sd` array
   - Reject duplicates or reserved names (`_sd`, `...`)
5. **Check holder binding (KB-JWT):** This proves the presenter actually owns the credential:
   - Get the holder's public key (`cnf.jwk`) from the issuer-signed credential
   - Verify the KB-JWT was signed with the matching private key
   - Check `aud` matches the verifier's `client_id`
   - Check `nonce` matches the request nonce
   - Check `iat` is recent
   - Check `sd_hash` matches `base64url(SHA-256(<issuer-jwt>~<disclosure-1>~...~<disclosure-n>~))`

The `sd_hash` is important: it's computed over the issuer-signed JWT and the selected disclosures (but not the KB-JWT itself), tying the proof to the exact set of disclosed claims. Without it, someone could steal a valid KB-JWT and attach it to different disclosures.

#### mdoc Verification

mdoc verification follows the same logic but uses CBOR/COSE instead of JSON/JWT:

1. **Parse** the CBOR structure
2. **Verify the COSE signature** (IssuerAuth) with the issuer's key from the trust list
3. **Check the MSO** (Mobile Security Object): docType, validity timestamps
4. **Check each item:** Hash the IssuerSignedItem, verify it matches the MSO's ValueDigests
5. **Check DeviceAuth:** COSE signature with the device key from the MSO, including a SessionTranscript that binds the response to the request

#### Revocation via Token Status Lists

Credentials can be revoked or suspended. The issuer publishes a **Token Status List**, a compressed bit array in a signed JWT.

Each credential has a status reference:
```json
{ "status_list": { "idx": 42, "uri": "https://issuer.example/status/1" } }
```

The verifier downloads the full list, decompresses it, and reads the bits at index 42:

| Bits per entry | Possible statuses |
|---------------|-------------------|
| 1 bit | VALID / INVALID |
| 2 bits | VALID / INVALID / SUSPENDED |
| 8 bits | Up to 256 custom statuses |

This is **privacy-preserving**: since the verifier always downloads the entire list, the issuer can't tell which credential is being checked.

## HAIP: The Interoperability Profile

OID4VP is flexible by design, but too much flexibility makes cross-border interoperability impossible. **HAIP** (OpenID4VC High Assurance Interoperability Profile) locks down the choices so every EU implementation is compatible:

| Area | HAIP requires |
|------|--------------|
| Signatures | ES256 (ECDSA with P-256) only |
| Response mode | `direct_post.jwt` or `dc_api.jwt` (always encrypted) |
| Encryption | ECDH-ES with P-256, A128GCM or A256GCM |
| Client ID schemes | `x509_san_dns` and `x509_hash` |
| Credential formats | SD-JWT VC (`dc+sd-jwt`) and mdoc |
| SD-JWT VC issuer key resolution | X.509 via the credential's `x5c` header chain, not JWT VC Issuer Metadata `jwks` / `jwks_uri` |
| Query language | DCQL |

Without HAIP, Germany and France could implement OID4VP with completely different algorithms and formats. HAIP is the agreement on exactly how everyone does it.

## Wallet Integration

Three ways to trigger the wallet from a browser:

### 1. W3C Digital Credentials API

A browser-native API, similar to how passkeys/WebAuthn work:

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

The browser handles wallet selection natively. No redirects, no QR codes. Browser support is limited:

| Browser | Support |
|---------|---------|
| Chrome 141+ (Sept 2025) | `openid4vp-v1-signed` and `unsigned` |
| Safari 26+ (Sept 2025) | `org-iso-mdoc` only (no OpenID4VP) |
| Firefox | Negative standards position |

The Safari gap is a real problem: it only supports mdoc through this API, not OpenID4VP. You need to handle both protocols for cross-browser support.

### 2. Same-Device Redirect

On mobile, the browser redirects to the wallet app via a custom URI:

```
openid4vp://?client_id=x509_san_dns:example.com
  &request_uri=https://example.com/request/abc123
```

The wallet opens, shows the consent screen, and POSTs the response back to the verifier.

### 3. Cross-Device QR Code

On desktop, the same `openid4vp://` URI is shown as a QR code. The user scans it with their phone's wallet app. The wallet fetches the request, shows the consent screen, and POSTs the response to the verifier's `response_uri`, just like in the same-device flow.

The key difference: in the cross-device case, the verifier's `direct_post` endpoint must **not** return a `redirect_uri` in its response. Otherwise the wallet would try to open that redirect on the phone, which isn't where the user's browser session lives. Instead, the relying party on the desktop side needs its own mechanism to detect that the response has arrived, for example by polling a status endpoint.

---

*In [Part 2]({{ '/2026/04/11/eudi-wallet-keycloak-part-2.html' | relative_url }}), we'll show how we integrated all of this into Keycloak, building a full OID4VP verifier as a Keycloak Identity Provider.*
