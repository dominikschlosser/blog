---
layout: default
title: "The EUDI Wallet Ecosystem in Practice: Issuance and Verification in Keycloak (Part 2)"
date: 2026-04-11
---

# The EUDI Wallet Ecosystem in Practice

*Part 2 - OID4VCI Issuance and OID4VP Verification in Keycloak*

In [Part 1]({{ '/2026/02/26/eudi-wallet-ecosystem.html' | relative_url }}), I explained the protocol pieces behind the EUDI wallet ecosystem: OpenID4VCI, OpenID4VP, SD-JWT, request binding, holder binding, DCQL, trust lists, and so on.

This post shows what that looks like in a real setup:

- **issuance** comes from **Keycloak 26.6.0** itself (with `oid4vc-vci` and `oid4vc-vci-preauth-code` experimental features enabled)
- **verification** comes from [keycloak-extension-oid4vp](https://github.com/ba-itsys/keycloak-extension-oid4vp)
- the end-to-end example comes from my [oid4vc-dev](https://github.com/dominikschlosser/oid4vc-dev) project, which I introduced in [an earlier post]({{ '/2026/02/28/oid4vc-developer-tools.html' | relative_url }})

This post uses [`examples/keycloak-issuer-verifier-app`](https://github.com/dominikschlosser/oid4vc-dev/tree/main/examples/keycloak-issuer-verifier-app) in `oid4vc-dev`. It combines one Keycloak realm, one small demo app, and one local wallet into a single flow.

All screenshots below were taken from that combined example in its default **HTTP mode**. That means verifier trust comes from a generated local trust list. The example also supports an HTTPS mode that switches trust resolution to issuer metadata.

On macOS, `oid4vc-dev` can also register itself as the handler for `openid-credential-offer://` and `openid4vp://` links. That means clicking the links in the example opens the wallet directly, which makes the local setup behave much closer to a real wallet integration.

## The Setup

At a high level, the setup looks like this:

```
User              Demo App                Keycloak + OID4VP extension          Wallet
 │                    │                                │                          │
 │ Log in             │                                │                          │
 │──────────────────► │ standard OIDC                  │                          │
 │                    │──────────────────────────────► │                          │
 │                    │ ◄──────────────────────────────│ app session              │
 │                    │                                │                          │
 │ Issue credential   │                                │                          │
 │──────────────────► │ create offer                   │                          │
 │                    │──────────────────────────────► │                          │
 │                    │ ◄──────────────────────────────│ offer URI                │
 │ Accept offer       │                                │                          │
 │──────────────────────────────────────────────────────────────────────────────► │
 │                    │                                │ OpenID4VCI pre-auth      │
 │                    │                                │ ◄────────────────────────│
 │                    │                                │ ────────────────────────►│
 │                    │                                │ SD-JWT credential        │
 │                    │                                │ ◄────────────────────────│
 │                    │                                │                          │
 │ Log in with wallet │                                │                          │
 │──────────────────► │ OIDC auth                      │                          │
 │                    │──────────────────────────────► │ wallet login             │
 │                    │                                │ ────────────────────────►│
 │                    │                                │ openid4vp://...          │
 │                    │                                │ ◄────────────────────────│
 │                    │                                │ direct_post VP           │
 │                    │ ◄──────────────────────────────│ logged in via wallet     │
```

The example keeps the moving parts small:

- one Keycloak realm acts as the issuer
- the same Keycloak realm also acts as the relying party login broker
- the OID4VP verifier logic lives in the extension
- the wallet is just `oid4vc-dev`

That setup shows where the protocol concepts from Part 1 appear in code and configuration.

## Part 1 Concepts, Mapped to This Example

| Part 1 concept | Where it shows up here |
|---|---|
| **Pre-authorized code flow** | The demo app asks Keycloak to create a credential offer, and the wallet redeems it without an extra browser login step |
| **Proof JWT / holder binding at issuance** | `oid4vc-dev` sends a proof JWT with its public key, and Keycloak binds that key into the SD-JWT VC |
| **`request_uri`** | The OID4VP extension does not put the full request into the `openid4vp://` link. It gives the wallet a `request_uri`, and the wallet fetches the signed request object from there |
| **DCQL** | The verifier config contains a DCQL query asking for one membership credential and specific claims from it |
| **`direct_post`** | After the user accepts, the wallet POSTs the presentation directly to the verifier endpoint |
| **KB-JWT / request binding** | The wallet's SD-JWT presentation contains a KB-JWT bound to the verifier request |
| **Issuer trust** | In HTTP mode, the verifier uses a generated trust list; in HTTPS mode, the example can resolve issuer metadata instead |


## Issuance with Keycloak

The issuance side is built into Keycloak itself. There is no extra verifier or wallet-specific extension involved.

The example defines a client scope called `membership-credential` with protocol `oid4vc`. That scope tells Keycloak what kind of credential it can issue:

```json
{
  "name": "membership-credential",
  "protocol": "oid4vc",
  "attributes": {
    "vc.credential_configuration_id": "membership-credential",
    "vc.credential_identifier": "membership-credential-id",
    "vc.format": "dc+sd-jwt",
    "vc.verifiable_credential_type": "https://credentials.example.com/membership",
    "vc.credential_signing_alg": "RS256",
    "vc.binding_required": "true",
    "vc.binding_required_proof_types": "jwt",
    "vc.cryptographic_binding_methods_supported": "jwk"
  }
}
```

In Keycloak, issuance is mostly **configuration plus mappers**.

- the client scope defines the credential type and format
- OID4VC protocol mappers define which user attributes become VC claims
- This credential requires holder binding but that can be configured per credential type
- Keycloak signs the final credential

In this example, the mappers pull these claims from the Keycloak user:

- `keycloak_user_id`
- `given_name`
- `family_name`
- `email`
- `preferred_username`
- plus generated metadata like `jti` and `iat`

So when `alice` is logged in, Keycloak is not querying some external issuer service. It already has the source data in the realm user model.

### The Issuance Flow

```
User              Demo App             Keycloak issuer            Wallet
 │                    │                        │                    │
 │ Click "Issue"      │                        │                    │
 │──────────────────► │ request offer          │                    │
 │                    │──────────────────────► │                    │
 │                    │ ◄──────────────────────│ offer response     │
 │ open offer         │                        │                    │
 │────────────────────────────────────────────────────────────────► │
 │                    │                        │ token request      │
 │                    │                        │ ◄──────────────────│
 │                    │                        │ access token       │
 │                    │                        │ ──────────────────►│
 │                    │                        │ credential request │
 │                    │                        │ + proof JWT        │
 │                    │                        │ ◄──────────────────│
 │                    │                        │ SD-JWT VC          │
 │                    │                        │ ──────────────────►│
```

The demo app does not create the credential itself. It just asks Keycloak to create a fresh offer for the configured credential type.

Keycloak can return that offer in different forms. It currently supports:

- `uri`
- `qr-code`

When `type=uri` is used, Keycloak returns JSON with the offer location. In this example, that is the `{issuer, nonce}` pair that the demo app turns into an `openid-credential-offer://` link.

When `type=qr-code` is used, Keycloak returns a PNG QR code directly. This can be rendered to allow the user to scan it with their phone for the cross-device flow.

In the running example, that produces a page like this:

![The combined example after it asked Keycloak to create a membership credential offer]({{ '/assets/images/eudi-keycloak-issue-page.png' | relative_url }})

What happens after the user opens that link in the wallet:

1. The wallet resolves the `openid-credential-offer://` URI to the real Keycloak offer endpoint
2. It reads the issuer metadata from `/.well-known/openid-credential-issuer`
3. It exchanges the pre-authorized code for an access token
4. It builds the **proof JWT**
5. It sends the credential request to Keycloak
6. Keycloak runs the configured OID4VC mappers, builds the SD-JWT VC, binds it to the wallet key, and signs it

### Why the proof matters

In Part 1, I described how issuance is not just "download a JWT". The wallet proves possession of a key, and the issuer binds the credential to that key.

The same thing happens here:

- `oid4vc-dev` creates the proof JWT
- the proof contains the wallet public key as a JWK
- Keycloak validates that proof
- the resulting SD-JWT VC contains the holder binding material in `cnf.jwk`

So later, during presentation, the wallet can prove: "I am the holder this credential was originally issued to."

## Verification with Keycloak

Verification is separate. Keycloak 26.6.0 does not do this by itself. For that, the example uses [keycloak-extension-oid4vp](https://github.com/ba-itsys/keycloak-extension-oid4vp), which plugs into Keycloak as an **Identity Provider**.

In Keycloak terms, the wallet login is handled as an external identity source:

- from Keycloak's point of view, the wallet acts like an external identity source
- the extension handles the OID4VP protocol details
- once verification succeeds, the extension hands Keycloak a brokered identity

The configured OID4VP provider in the example looks roughly like this:

```json
{
  "providerId": "oid4vp",
  "alias": "oid4vp",
  "config": {
    "sameDeviceEnabled": "true",
    "crossDeviceEnabled": "false",
    "walletScheme": "openid4vp://",
    "responseMode": "direct_post",
    "clientIdScheme": "plain",
    "enforceHaip": "false",
    "allowedIssuers": "http://localhost:8080/realms/wallet-app-demo",
    "trustListUrl": "http://host.docker.internal:8090/keycloak-trustlist.jwt",
    "userMappingClaim": "keycloak_user_id",
    "dcqlQuery": "{...}"
  }
}
```

To keep things simple, this example doesn't use HAIP:

- `direct_post`, not `direct_post.jwt`
- `plain`, not `x509_san_dns` or `x509_hash`
- HAIP enforcement disabled
- same-device flow only

### The Verification Flow

```
User              Demo App             Keycloak            OID4VP Ext.           Wallet
 │                    │                    │                     │                   │
 │ Start wallet login │                    │                     │                   │
 │──────────────────► │ OIDC auth +        │                     │                   │
 │                    │ kc_idp_hint=oid4vp │                     │                   │
 │                    │──────────────────► │ start broker login  │                   │
 │                    │                    │───────────────────► │                   │
 │                    │                    │                     │ wallet page +     │
 │                    │                    │                     │ openid4vp://...   │
 │                    │                    │                     │ ────────────────► │
 │                    │                    │                     │ request_uri fetch │
 │                    │                    │                     │ ◄──────────────── │
 │                    │                    │                     │ signed request    │
 │                    │                    │                     │ ────────────────► │
 │                    │                    │                     │ direct_post VP    │
 │                    │                    │                     │ ◄──────────────── │
 │                    │                    │                     │ verify SD-JWT,    │
 │                    │                    │                     │ KB-JWT, trust     │
 │                    │                    │ brokered identity   │                   │
 │                    │                    │ ◄────────────────── │                   │
 │                    │ ◄──────────────────│ user logged in      │                   │
```

The wallet login page generated by Keycloak looks like this in the example:

![Keycloak showing the wallet login page generated by the OID4VP extension]({{ '/assets/images/eudi-keycloak-wallet-login.png' | relative_url }})

That button is where the protocol starts.

The link behind it is an `openid4vp://` URI containing a short `request_uri`. This is the same "pass by reference" pattern from Part 1:

- the browser only sees a small wallet link
- the wallet fetches the real signed request object from Keycloak
- the request object contains the actual OID4VP request parameters

The extension also supports the cross-device flow via a rendered QR code, but the example defaults to the same-device flow for simplicity.

### What Is inside the Request Object?

The relevant fields are:

- `client_id`
- `response_mode=direct_post`
- `response_uri`
- `nonce`
- `state`
- `dcql_query`

In this example, the DCQL query asks for one SD-JWT credential of type `https://credentials.example.com/membership` and requests these claims:

- `keycloak_user_id`
- `given_name`
- `family_name`
- `email`

This means:

- **DCQL** says what the verifier wants
- **nonce** and **state** bind the response to this request
- **response_uri** tells the wallet where to POST the response

### Credential Verification

Once the wallet POSTs the presentation, `keycloak-extension-oid4vp` processes the response:

1. It resolves the saved request context from the earlier `request_uri` fetch
2. It checks that the callback matches the original verifier request
3. It parses the returned VP token
4. For SD-JWT, it verifies:
   - the issuer signature
   - the disclosed claims
   - the KB-JWT
   - the issuer trust configuration
   - the requested credential type
5. It extracts the configured mapping claim, here `keycloak_user_id`
6. It turns the verified result into a Keycloak brokered identity

## Linking the Presentation Back to the User

The claim that links issuance and verification in this example is `keycloak_user_id`.

During issuance:

- Keycloak reads the user's internal ID from the user profile
- it places that value into the credential as `keycloak_user_id`

During verification:

- the extension asks the wallet to present that claim
- after successful verification, it uses that claim as the stable subject mapping

This lets Keycloak link the verified wallet login back to the same user that originally received the credential.

## oid4vc-dev

`oid4vc-dev` appears here in two separate roles.

First, it is the wallet used in the example. It accepts the issuance offer, stores the credential, and later presents it back to the verifier.

Second, it makes the flow inspectable.

After issuance, the wallet UI shows the new credential:

![The issued membership credential stored in oid4vc-dev]({{ '/assets/images/eudi-keycloak-wallet-ui.png' | relative_url }})

And after verification, the app session is back, but now the login method is the wallet:

![The combined example after the wallet presentation has been verified by Keycloak]({{ '/assets/images/eudi-keycloak-wallet-success.png' | relative_url }})

The examples in `oid4vc-dev` make the flow inspectable locally: you can see the offer URIs, request URIs, DCQL queries, credentials, and presentations directly.

## Trust: Two Local Modes

The combined example supports two verifier trust setups:

### HTTP mode

This is the default local setup and the one used in the screenshots above.

- Keycloak runs on `http://localhost:8080`
- the demo app serves a generated trust list
- the OID4VP extension uses that trust list to trust the issuer

Using Trust Lists is the default verification mode for the EUDI-Wallet and also mandated in HAIP.

### HTTPS mode

In this mode:

- Keycloak runs on `https://localhost:8443`
- the verifier can resolve signing keys from issuer metadata (`/.well-known/jwt-vc-issuer`)

Using the issuer metadata endpoint is an alternative to trust lists, outside HAIP.
It requires HTTPS though.

## Try It Yourself

If you want to run the exact setup from this post, clone [oid4vc-dev](https://github.com/dominikschlosser/oid4vc-dev) and then run:

```bash
cd examples/keycloak-issuer-verifier-app
./start.sh
```

Then:

1. Sign in as `alice` / `alice`
2. Issue the membership credential
3. Open the offer in `oid4vc-dev`
4. Log in again with the wallet

If you only want the smaller pieces, `oid4vc-dev` also contains dedicated examples for:

- issuance only: `examples/keycloak-issuer-wallet`
- verification only: `examples/keycloak-verifier-oid4vp`

---

*In Part 3, we will make this setup HAIP-conformant, which requires some changes like using Authorization Code Flow for issuance and encrypted responses for verification.*
