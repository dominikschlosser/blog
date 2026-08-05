---
layout: default
title: "Credential Formats in the EUDI Ecosystem: SD-JWT and mdoc compared"
date: 2026-08-05
---

# Credential Formats in the EUDI Ecosystem

*From the general idea down to the bytes*

Most developers who work on EUDI wallet integrations learn SD-JWT first. It is JSON, it is base64url, and you can paste it into a decoder and read it. Then a verifier asks for an `mso_mdoc` credential, you print one, and you get a wall of hex.

The two formats implement the same idea. This post walks that idea from the concept down to individual bytes, using SD-JWT as the reference point and spending most of the detail on mdoc.

## General Idea

Neither format redacts anything at presentation time.

![Issuer, holder and verifier, and what each one does with the salted digests]({{ '/assets/images/sd-jwt-mdoc-concept.png' | relative_url }})

The issuer signs a digest of each salted claim. Leaving a claim out therefore cannot break the signature, since the signature only ever covered the digest. A withheld claim still leaves that digest behind, and the salt is what stops anyone from guessing the value and confirming the guess by hashing it.

The rest of this post follows that mechanism through both encodings, JSON and base64url for SD-JWT, CBOR and COSE for mdoc.

## Encoding

### SD-JWT

SD-JWT ([RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html)) is one ASCII string, separated by tildes. The credential profile on top of it, SD-JWT VC, is what defines `vct` and the `dc+sd-jwt` type.

```
<Issuer-signed JWT>~<Disclosure>~<Disclosure>~...~<KB-JWT>
```

The first segment is a normal compact JWS. Everything after the first tilde sits outside its signature, which is exactly why a wallet can present a subset by concatenating fewer disclosures.

```
header  { "alg": "ES256", "typ": "dc+sd-jwt", "kid": "...", "x5c": ["MIIB..."] }

payload {
  "iss": "https://issuer.example",
  "vct": "urn:eudi:pid:1",
  "iat": 1770000000,
  "exp": 1772592000,
  "cnf": { "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." } },
  "status": { "status_list": { "uri": "https://issuer.example/status/1", "idx": 42 } },
  "_sd_alg": "sha-256",
  "_sd": [ "kR3vX...", "9Bq2t...", "hXs7L..." ]
}
```

The `_sd` array holds one digest per hidden claim. Each disclosure is base64url over a JSON array:

```
[ "<salt>", "family_name", "Müller" ]     a named claim
[ "<salt>", "AT" ]                        an array element
```

Older credentials use `vc+sd-jwt` as the `typ` value instead of `dc+sd-jwt`. Both values are in use.

### mdoc

mdoc comes from ISO/IEC 18013-5. It is CBOR, then base64url or hex for transport.

```
DeviceResponse = {
  "version": "1.0",
  "documents": [ Document ],
  "status": 0
}

Document = {
  "docType": "eu.europa.ec.eudi.pid.1",
  "issuerSigned": IssuerSigned,
  "deviceSigned": DeviceSigned          only at presentation time
}

IssuerSigned = {
  "nameSpaces": {
    "eu.europa.ec.eudi.pid.1": [
      #6.24(bstr .cbor IssuerSignedItem),      the revealed claims
      #6.24(bstr .cbor IssuerSignedItem), ... ] },
  "issuerAuth": #6.18(COSE_Sign1)              the signed MSO
}

IssuerSignedItem = {
  "digestID": 3,
  "random": h'8798645b...',                    the salt
  "elementIdentifier": "family_name",
  "elementValue": "Müller"
}
```

`#6.24(bstr)` is CBOR notation for an embedded CBOR data item, meaning tag 24 wrapping a byte string that itself holds CBOR. mdoc uses it everywhere. It exists so that bytes can be hashed and signed exactly as they arrived, with no re-encoding step in between.

At issuance a wallet normally receives only the `IssuerSigned` part. `DeviceResponse` is the wrapper built at presentation time. A parser has to accept both.

Roughly: the JWT payload corresponds to the MSO, a disclosure corresponds to an `IssuerSignedItem`, and the tilde separated list corresponds to the CBOR array under `nameSpaces`. The mdoc concepts with no SD-JWT counterpart are namespaces and the `digestID` index.

## Digest Storage and Lookup

SD-JWT keeps a flat array of digest strings inside the signed payload. Lookup is by content: you hash the disclosure you received and search `_sd` for that exact string.

SD-JWT supports nesting directly. A disclosed object can carry its own `_sd` array, so subclaims are selectively disclosable to any depth. A hidden array element appears as a placeholder object sitting in the array:

```json
"address": { "_sd": [ "Ab1...", "Cd2..." ], "country": "DE" },
"nationalities": [ { "...": "Ef3..." }, "DE" ]
```

mdoc keeps its digests in the Mobile Security Object, in a two level map of namespace to digest ID:

```
MobileSecurityObject = {
  "version": "1.0",
  "digestAlgorithm": "SHA-256",
  "docType": "eu.europa.ec.eudi.pid.1",
  "valueDigests": {
    "eu.europa.ec.eudi.pid.1":    { 0: h'a1c4...', 1: h'7f09...', 3: h'22be...' },
    "eu.europa.ec.eudi.pid.de.1": { 4: h'9d31...' } },
  "deviceKeyInfo": { "deviceKey": COSE_Key },
  "validityInfo": { "signed": ..., "validFrom": ..., "validUntil": ... },
  "status": { "status_list": { "uri": ..., "idx": 42 } }
}
```

and it travels as `issuerAuth.payload = #6.24(bstr .cbor MobileSecurityObject)`.

Lookup is by index: you read `digestID` from the item you received and fetch `valueDigests[namespace][digestID]`.

mdoc has no nesting. An element is either revealed or it is not, and if `elementValue` is a map or an array, it is revealed completely. Where SD-JWT would nest, mdoc adds more flat elements or another namespace. The German PID does exactly that, with national additions in `eu.europa.ec.eudi.pid.de.1` next to the base namespace.

Both formats reveal how much was withheld, even though they hide the values. An SD-JWT verifier sees how many digests sit in `_sd` and how many disclosures arrived. An mdoc verifier sees the whole `valueDigests` map, so it knows how many elements exist per namespace and which digest IDs were held back.

## Byte Level Walkthrough

Same claim in both formats: `family_name` with the value `Müller`. Every value below is computed, so you can check it yourself.

![How each verifier turns a received claim back into a digest and looks it up]({{ '/assets/images/sd-jwt-mdoc-digest-lookup.png' | relative_url }})

### SD-JWT

Start with a random salt of 128 bits, base64url encoded, and build the disclosure array:

```json
["eluV5Og3gSNII8EYnsxA_A","family_name","Müller"]
```

Base64url the JSON:

```
WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwiZmFtaWx5X25hbWUiLCJNw7xsbGVyIl0
```

Hash that string:

```
digest = base64url( SHA-256( ASCII bytes of the string above ) )
       = irRpmiW72UQiqAclgJInkXvXbRgUdERjxg6MuD_0BTQ
```

The hash input is the base64url text, not the JSON behind it. This is why the exact JSON serialization does not matter to a verifier. It hashes the string it received and never re-serializes anything.

The digest goes into `_sd` inside the signed payload. The base64url string goes on the wire only when the claim is disclosed.

### mdoc

Start with a random salt. In mdoc the field is called `random`. Then build the item:

```
{ "digestID": 3,
  "random": h'8798645b87b0a4b3e2d1f0c6a5947e3d',
  "elementIdentifier": "family_name",
  "elementValue": "Müller" }
```

CBOR encode it and wrap the result in tag 24. Here it is as annotated hex, the notation that [cbor.me](https://cbor.me) prints, with the raw bytes on the left and their meaning on the right:

```
D8 18                                           # tag(24), embedded CBOR
   58 56                                        # bytes(86)
      A4                                        # map(4)
         68                                     # text(8)
            6469676573744944                    # "digestID"
         03                                     # unsigned(3)
         66                                     # text(6)
            72616E646F6D                        # "random"
         50                                     # bytes(16)
            8798645B87B0A4B3E2D1F0C6A5947E3D    # the salt
         71                                     # text(17)
            656C656D656E744964656E746966696572  # "elementIdentifier"
         6B                                     # text(11)
            66616D696C795F6E616D65              # "family_name"
         6C                                     # text(12)
            656C656D656E7456616C7565            # "elementValue"
         67                                     # text(7)
            4DC3BC6C6C6572                      # "Müller"
```

Now hash all 90 of those bytes, starting at `D8`:

```
SHA-256 = e754cec185c732fe47b80997c72b5b8558fc1b7ae9c144873b2eca18da836952
```

Hash only the 86 bytes of the map, starting at `A4`, and you get a different value:

```
SHA-256 = 641edac1bb8e17c243a93a45c3e6905beb458cce118a87c26117fe43b2c01775
```

Both decode to the same map. Only the first matches the digest in the MSO.

The same rule applies to any round trip. Decoding an item into a map and re-encoding it can change key order or integer widths, and either one changes the digest. Keep the bytes as they arrived and hash those.

The digest goes into `valueDigests["eu.europa.ec.eudi.pid.1"][3]` as a raw byte string, with no base64 anywhere. The 90 tag 24 bytes go into `nameSpaces` when the element is disclosed.

## The Issuer Signature

SD-JWT uses plain JWS. The signing input is literally the first two segments of the token:

```
signing input = ASCII( base64url(header) + "." + base64url(payload) )
signature     = ES256 over SHA-256(signing input)
```

If you can print the token, you are looking at the exact bytes that were signed. The issuer certificate chain sits in `x5c` inside the protected header, so the chain is covered by the signature.

mdoc uses COSE_Sign1, which inserts a step:

```
issuerAuth = #6.18([ protected:   bstr .cbor header,
                     unprotected: map,
                     payload:     bstr,
                     signature:   bstr ])
```

COSE signs a structure that both sides rebuild, so those four fields are inputs to it rather than the signed bytes themselves:

```
Sig_structure = [ "Signature1",
                  protected,        the protected bstr, exactly as sent
                  external_aad,     h'' for mdoc
                  payload ]         #6.24(bstr .cbor MSO)

signature = ES256 over SHA-256( CBOR(Sig_structure) )
```

The headers are integer keyed:

```
protected   { 1: -7 }              alg = ES256
unprotected { 33: <cert DER> }     x5chain
```

In COSE, `1` is alg, `4` is kid and `33` is x5chain. In a COSE_Key, `1` is kty, `-1` is crv, `-2` is x and `-3` is y.

In a JWS the `x5c` chain sits in the protected header and is covered by the signature. mdoc carries `x5chain` in the unprotected header of `issuerAuth`, so COSE itself protects nothing about it. RFC 9360 is explicit that an unprotected `x5chain` lets an intermediary add or remove certificates, and that the end-entity certificate has to be integrity protected some other way, for example by an `x5t` in the protected header.

COSE does not stop a substituted certificate. An attacker who swaps in a chain of their own can re-sign the MSO with the matching key and the COSE signature will verify perfectly. It fails at the next step, when the chain has to validate against a trust anchor the verifier already holds. Treat the embedded chain as untrusted input until that check has passed.

## Presentation in Depth

Everything so far describes a credential sitting in storage. A stored credential is replayable by anyone who copies it, so both formats add a second signature made by the holder at presentation time. That signature carries two bindings at once, the pair introduced in [Part 1]({{ '/2026/02/26/eudi-wallet-ecosystem.html' | relative_url }}).

**Holder binding** proves the presenter controls the key the issuer named in the credential. That key is `cnf.jwk` in SD-JWT and `deviceKeyInfo.deviceKey` in the MSO for mdoc.

**Request binding** ties the response to one specific request, so a captured presentation cannot be replayed at another verifier.

Both formats cover both with a single holder signature. What differs is where the request binding lives. SD-JWT puts it in claims inside the Key Binding JWT, `aud` and `nonce`, which travel with the presentation and can be read directly. mdoc puts it in the `SessionTranscript`, which never travels and which each side rebuilds from its own copy of the request.

### SD-JWT: Key Binding JWT

The wallet does this, in order:

1. Keep the issuer JWT byte for byte. Nothing about it changes.
2. Select the disclosures that answer the query. A nested claim needs its parent disclosure included as well, otherwise the child has nothing to attach to.
3. Concatenate what will be sent, ending with a tilde:

   ```
   issuer_jwt~disc_a~disc_c~
   ```

4. Hash that entire string, trailing tilde included, using the same algorithm as `_sd_alg`:

   ```
   sd_hash = base64url( SHA-256( issuer_jwt~disc_a~disc_c~ ) )
   ```

5. Build and sign the key binding JWT with the private key matching `cnf.jwk`:

   ```
   header  { "alg": "ES256", "typ": "kb+jwt" }
   payload {
     "iat": 1770003600,
     "aud": "<verifier client_id>",
     "nonce": "<nonce from the request>",
     "sd_hash": "<from step 4>"
   }
   ```

6. Append it, producing `issuer_jwt~disc_a~disc_c~kb_jwt`.

The audience is not always the `client_id`. Over the Digital Credentials API it MUST be the origin prefixed with `origin:`, and OpenID4VP is explicit that this holds even for signed requests, so a client identifier being present does not change it. A verifier that compares `aud` against its `client_id` in both cases will reject every DC API presentation it receives.

### mdoc: DeviceAuth

The mdoc side works differently:

1. Copy `issuerAuth` raw into the response. Do not decode and re-encode it.
2. Filter `nameSpaces` down to the requested elements, copying each item's original bytes for the same reason.
3. Build the `SessionTranscript`, whose shape depends on how the request was invoked. See below.
4. Build the structure that will actually be signed:

   ```
   DeviceAuthentication = [ "DeviceAuthentication",
                            SessionTranscript,
                            DocType,
                            DeviceNameSpacesBytes ]

   payload = #6.24(bstr .cbor DeviceAuthentication)
   ```

   `DeviceNameSpacesBytes` is `#6.24` of an empty map when the wallet contributes no device signed elements, which is the normal case in OID4VP. The identical bytes also go into `deviceSigned.nameSpaces`.

5. Sign a COSE_Sign1 over that payload with the private key matching `deviceKeyInfo.deviceKey`, then **remove the payload** before sending. It is detached, and the COSE_Sign1 in `deviceAuth.deviceSignature` is untagged.
6. Assemble the `DeviceResponse`.

The verifier never receives the signed payload. It rebuilds `DeviceAuthentication` from its own request state, re-attaches it, and only then verifies. A mismatch means the holder signed a different request.

### The Session Transcript

![The chain from request parameters down to the signed payload, built independently on both sides]({{ '/assets/images/sd-jwt-mdoc-session-transcript.png' | relative_url }})

```
SessionTranscript = [ DeviceEngagementBytes, EReaderKeyBytes, Handover ]
```

The first two members exist for proximity flows over NFC or Bluetooth. OpenID4VP 1.0 requires both to be `null` and prescribes the `Handover`, so online there is no free choice. Which of the two applies is decided by how the request was invoked.

**Invocation via redirects**, meaning `direct_post`, `direct_post.jwt` and redirect based flows:

```cddl
OpenID4VPHandover = [
  "OpenID4VPHandover",
  OpenID4VPHandoverInfoHash        ; sha-256 of OpenID4VPHandoverInfoBytes
]

OpenID4VPHandoverInfoHash  = bstr
OpenID4VPHandoverInfoBytes = bstr .cbor OpenID4VPHandoverInfo

OpenID4VPHandoverInfo = [ clientId, nonce, jwkThumbprint, responseUri ]
```

`clientId` is the `client_id` request parameter including its Client Identifier Prefix. `jwkThumbprint` is the RFC 7638 SHA-256 thumbprint of the verifier key used to encrypt the response, as a byte string, and `null` when the response is not encrypted. The last element is whichever of `redirect_uri` or `response_uri` the response mode actually uses. All of them are taken from the signed request object when the request is signed, and from the query parameters when it is not.

**Invocation via the Digital Credentials API**, where there is no client identifier and no response URI:

```cddl
OpenID4VPDCAPIHandover = [
  "OpenID4VPDCAPIHandover",
  OpenID4VPDCAPIHandoverInfoHash
]

OpenID4VPDCAPIHandoverInfoBytes = bstr .cbor OpenID4VPDCAPIHandoverInfo

OpenID4VPDCAPIHandoverInfo = [ origin, nonce, jwkThumbprint ]
```

Here `jwkThumbprint` is present for response mode `dc_api.jwt` and `null` for `dc_api`.

The origin in the handover MUST NOT be prefixed. The `aud` of a Key Binding JWT over the same API MUST be the origin prefixed with `origin:`, for example `origin:https://verifier.example`.

ISO 18013-7 Annex B defines a third handover, which mixes in a wallet generated nonce:

```
clientIdHash    = SHA-256( CBOR([ client_id,    mdocGeneratedNonce ]) )
responseUriHash = SHA-256( CBOR([ response_uri, mdocGeneratedNonce ]) )
Handover        = [ clientIdHash, responseUriHash, nonce ]
```

`mdocGeneratedNonce` is fresh per presentation, so the verifier cannot derive it from the request. That profile transports it in the `apu` header of the encrypted response. OpenID4VP 1.0 does not define this handover and does not reference ISO 18013-7.

Both sides compute the transcript independently and never exchange it, which is what makes a captured response useless against any other request. Every input has to match byte for byte:

- **`client_id` including its prefix.** `x509_san_dns:verifier.example` and `verifier.example` are different strings.
- **The response URI exactly as the wallet saw it.** A trailing slash, a default port written out, or `http` against `https` all produce a different hash.
- **The JWK thumbprint.** Both sides have to build the RFC 7638 canonical JSON from the same members and agree on which key in `client_metadata.jwks` is the encryption key.

If any of them differ, the verifier rebuilds a different payload from the one the wallet signed, and the COSE verification fails.

### Proof Coverage

Two mechanisms do different jobs here. `_sd` sits in the issuer-signed payload and protects the claim **values**. `sd_hash` sits in the holder-signed key binding JWT and protects the **selection**, meaning which disclosures were actually sent. mdoc has the first and no equivalent of the second.

![Brackets showing which bytes each signature covers in both formats]({{ '/assets/images/sd-jwt-mdoc-signature-coverage.png' | relative_url }})

The difference only shows up once you ask who is changing the presentation and when:

| Change to the presentation | SD-JWT | mdoc |
|---|---|---|
| The wallet sends fewer claims while building the presentation | By design, nothing breaks | By design, nothing breaks |
| An intermediary removes claims from a presentation in transit | Rejected, `sd_hash` stops matching and cannot be recomputed without the holder key | Accepted, no signature covers which elements are present |
| Anyone alters a claim value | Rejected, the `_sd` digest stops matching | Rejected, the MSO digest stops matching |
| A malicious wallet appends a claim the issuer never signed | Rejected, but only by the "every disclosure is referenced" check, since the wallet can re-sign `sd_hash` | Rejected, the MSO lists no digest for it |

Row one is ordinary selective disclosure. Row two is where the formats differ. An mdoc device signature covers the session transcript and the doctype, never `issuerSigned`, so a captured `DeviceResponse` can be stripped down and still verify.

Two consequences carry into the checklists below. An mdoc verifier has to confirm that the elements it asked for are present, because a passing signature does not tell it that. An SD-JWT verifier has to reject disclosures the credential does not reference, because `sd_hash` alone cannot catch row four.

### Verifier Checklists

For SD-JWT:

1. The presentation parses.
2. Every disclosure received is referenced by the credential. An unreferenced disclosure belongs to some other credential and discloses nothing here.
3. `vct` matches what was requested. Trusting the wallet to return the right type would let any held credential satisfy the request.
4. The issuer certificate chains to a trust anchor you already hold.
5. The issuer signature verifies.
6. The credential is within its `nbf` and `exp` window.
7. The credential is not revoked, per the status list.
8. A key binding JWT is present and typed `kb+jwt`.
9. The credential carries `cnf.jwk`, and the key binding signature verifies with that key.
10. `sd_hash` matches the presentation as received, up to and including the final tilde.
11. `nonce` matches this request.
12. `aud` is this verifier (or this origin, over the DC API).

For mdoc:

1. The presentation parses as a `DeviceResponse`.
2. `docType` matches what was requested.
3. The issuer certificate from `x5chain` chains to a trust anchor you already hold.
4. The `issuerAuth` signature verifies.
5. The credential is within the window in `validityInfo`.
6. Every disclosed element hashes to the digest the issuer signed for it. `issuerAuth` covers only the MSO, so without this check the element values are unverified.
7. Rebuild the `SessionTranscript` from your own request state and verify `DeviceAuth` against it.
8. The elements you asked for are present.

Steps 2 and 6 in the mdoc list, and steps 2 and 3 in the SD-JWT list, are the same check in both formats. They stop a wallet from satisfying a request with something the verifier never asked for.

## Format Reference

| Concept | SD-JWT | mdoc |
|---|---|---|
| Encoding | JSON, base64url, ASCII throughout | CBOR and COSE, binary throughout |
| Outer container | tilde separated compact string | `DeviceResponse` (or bare `IssuerSigned`) |
| Credential type | `vct`, in the payload | `docType`, in the MSO and the Document |
| Grouping of claims | nested JSON objects, any depth | flat namespaces, no nesting |
| Signed object | the JWT payload | the MSO, inside the COSE_Sign1 payload |
| Issuer signature | JWS ES256 over `header.payload` | COSE_Sign1 ES256 over `Sig_structure` |
| Issuer certificate | `x5c`, protected header, signed | `x5chain` (33), unprotected, not signed |
| Salt | first element of the disclosure array, base64url | `random`, a CBOR byte string in the item |
| Digest input | the base64url disclosure string | the full `#6.24(bstr)` item encoding |
| Digest output | base64url string in `_sd` | raw byte string in `valueDigests[ns][id]` |
| Digest lookup | by value, searched in `_sd` | by integer `digestID`, per namespace |
| Hash agility | `_sd_alg`, defaults to sha-256 | `digestAlgorithm` (SHA-256 / 384 / 512) |
| Holder public key | `cnf.jwk` in the payload | `deviceKeyInfo.deviceKey` in the MSO |
| Holder binding | KB-JWT signed with the `cnf.jwk` key | DeviceAuth signed with the device key |
| Request binding | `aud` and `nonce` inside the KB-JWT | the `SessionTranscript`, never transmitted |
| Proof covers claims sent | yes | no |
| Validity window | `iat`, `nbf`, `exp` in the payload | `validityInfo` signed, validFrom, validUntil |
| Revocation | `status.status_list` in the payload | `status.status_list` in the MSO |
| Disclosure unit | any claim, subclaim or array element | one whole element, all or nothing |
| Linkability | one reused signature links presentations | same, batch issuance is the answer |

## Common Pitfalls

Each of these surfaces as a digest or signature mismatch rather than as a specific error.

**Building and reading the credential**

1. **Hash the tag, not the map.** The MSO digest covers the complete `#6.24(bstr ...)` encoding of the item. Hashing the decoded inner map, or re-encoding it first, gives a value that matches nothing.
2. **Two layers of tag 24.** The MSO is tag 24 wrapped inside the COSE payload, and each item is tag 24 wrapped inside `nameSpaces`. You unwrap twice on the way in, and you must not unwrap at all before hashing.
3. **A valid issuer signature proves nothing about the values.** `issuerAuth` covers the MSO only. Until you recompute every item digest, a wallet can put anything it likes in `elementValue` and the signature still verifies.
4. **Dates are CBOR tags.** A full date (`YYYY-MM-DD`) is tag 1004 and a timestamp is tag 0. A verifier that expects a plain text string will reject real PIDs, and an issuer that emits plain strings will be rejected by real verifiers.

**Building and checking a presentation**

5. **Filter by copying bytes.** When you drop elements from `nameSpaces`, copy the raw item encodings and copy `issuerAuth` untouched. Decoding and re-encoding either one is enough to break the digests or the issuer signature.
6. **`issuerAuth` is tagged, `deviceSignature` is not.** `issuerAuth` is a tag 18 COSE_Sign1 with an attached payload. The `deviceSignature` inside `deviceAuth` is untagged with a detached payload. One code path cannot handle both unless it is told which it is dealing with.
7. **The invocation decides the handover.** OpenID4VP 1.0 prescribes `OpenID4VPHandover` for redirects and `OpenID4VPDCAPIHandover` for the DC API. Code that still builds the ISO 18013-7 handover is following a different profile and will not interoperate.
8. **Every transcript input is compared byte for byte.** The `client_id` prefix, the exact response URI, and the RFC 7638 thumbprint of the response encryption key. A trailing slash is enough to fail the whole presentation.
9. **`sd_hash` includes the trailing tilde.** It covers the presentation up to and including the final tilde before the key binding JWT. Trimming it produces a presentation that no verifier will accept.
10. **The origin is prefixed in one place and bare in the other.** Over the DC API the Key Binding JWT `aud` MUST be `origin:https://verifier.example`, while the origin inside `OpenID4VPDCAPIHandoverInfo` MUST NOT carry that prefix.
11. **A passing mdoc signature does not mean you got what you asked for.** Check that the requested elements are present, since the device signature does not cover them.

## Closing

Both formats follow the same sequence. Hash a salted claim, sign the digests, reveal a subset, re-hash and compare. The differences come from the encoding. mdoc hashes bytes with their tags and length prefixes included, keeps its digests in an integer index per namespace, and rebuilds both the issuer signing input and the holder signing input from context that never travels with the message.

To get the byte level answer for a specific credential, [eudi-dev](https://github.com/dominikschlosser/eudi-dev) decodes and verifies both formats and prints the digest it computed next to the digest the issuer signed. The same decoder runs in the browser at [eudi-test.dev/decoder](https://eudi-test.dev/decoder), and [eudi-test.dev](https://eudi-test.dev) is a hosted wallet with a demo issuer and verifier to point your own implementation at. It is a shared instance, so keep real personal data out of it.
