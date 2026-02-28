---
layout: default
title: "Two Tools That Make OID4VC Development Less Painful"
date: 2026-02-28
---

# Two Tools That Make OID4VC Development Less Painful

Building OID4VC integrations means dealing with a lot of encoded tokens, complex flows, and not a lot of tooling to help. You end up copy-pasting tokens into jwt.io, manually decoding CBOR, writing throwaway scripts to simulate a wallet, and hoping for the best. So I built two tools to fix that.

## oid4vc-dev: A Swiss Army Knife for OID4VC Development

[oid4vc-dev](https://github.com/dominikschlosser/oid4vc-dev) is a CLI tool (and web UI) that handles everything you need during development. Paste in a credential, and it figures out the format and decodes it. Point it at a QR code on your screen, and it grabs the content. Need a test credential? It generates one. Want to see what's flying between your verifier and a wallet? It can proxy and inspect the traffic live.

Here's what it can do:

| Command | What it does |
|---------|-------------|
| `decode` | Auto-detects and parses SD-JWTs, mDOCs, JWT VCs, OID4VCI offers, trust lists |
| `validate` | Verifies signatures, checks expiration, validates against trust lists |
| `issue` | Generates test credentials (SD-JWT, JWT, mDOC) |
| `wallet` | A full stateful test wallet with CLI-driven OID4VP and OID4VCI flows |
| `proxy` | Reverse proxy that intercepts and classifies wallet traffic with a live dashboard |
| `serve` | Web UI for pasting and inspecting credentials in the browser |
| `dcql` | Generates DCQL queries from existing credentials |

A few examples:

```bash
# Decode a credential from a QR code on your screen
oid4vc-dev decode --screen

# Generate a PID credential for testing
oid4vc-dev wallet generate-pid

# Validate a credential against an issuer's public key
oid4vc-dev validate --key issuer-key.pem credential.txt

# Generate a DCQL query from an existing credential
oid4vc-dev dcql credential.txt
```

The test wallet deserves special mention. It's a fully stateful wallet that can accept credential offers, respond to presentation requests, and persist credentials to disk. You can register it as a URL handler on your OS, so clicking `openid4vp://` links opens it directly. It's not meant to replace a real wallet, but it's incredibly useful for testing your verifier or issuer without needing to pull out your phone every time.

You can install it as a Go binary, download a release, or run it in Docker:

```bash
# Install from source
go install github.com/dominikschlosser/oid4vc-dev@latest

# Or run via Docker (includes the web UI)
docker run -p 8085:8085 ghcr.io/dominikschlosser/oid4vc-dev
```

**Important:** This is a development tool. The wallet server exposes unauthenticated endpoints and should never be exposed to untrusted networks.

## testcontainers-oid4vc: Integration Testing Without a Real Wallet

The second tool solves a different problem: how do you write automated integration tests for your OID4VP verifier or OID4VCI issuer?

[testcontainers-oid4vc](https://github.com/dominikschlosser/testcontainers-oid4vc) is a Testcontainers module that spins up a containerized wallet in your JUnit tests. It comes with pre-configured PID credentials, auto-accept mode for hands-free testing, and a fluent Java API.

Add it to your Maven project:

```xml
<dependency>
    <groupId>io.github.dominikschlosser</groupId>
    <artifactId>testcontainers-oid4vc</artifactId>
    <version>1.1.1</version>
    <scope>test</scope>
</dependency>
```

A basic test looks like this:

```java
@Testcontainers
class Oid4vpVerifierTest {
    @Container
    static Oid4vcContainer wallet = new Oid4vcContainer()
        .withHostAccess();

    @Test
    void walletCanPresentPid() {
        // Your verifier creates a presentation request...
        String requestUri = "openid4vp://...";

        // The container accepts it and returns the response
        PresentationResponse response = wallet.acceptPresentationRequest(requestUri);

        assertThat(response.redirectUri()).isNotNull();
    }
}
```

You can customize the wallet's credentials:

```java
Oid4vcContainer wallet = new Oid4vcContainer()
    .withPidClaims(new SdJwtPidClaims()
        .givenName("Jane")
        .familyName("Doe")
        .birthdate("1990-01-15"));
```

Or configure it for specific scenarios:

```java
Oid4vcContainer wallet = new Oid4vcContainer()
    .withStatusList()              // expose a status list endpoint
    .withPreferredFormat(CredentialFormat.SD_JWT)
    .withoutAutoAccept()           // require explicit acceptance
    .withoutDefaultPid();          // start with an empty wallet
```

It also ships with a credential builder for creating test credentials on the fly:

```java
String sdJwt = new SdJwtCredentialBuilder()
    .vct("urn:example:credential:1")
    .issuer("https://issuer.example.com")
    .claim("given_name", "Jane")
    .ttl(Duration.ofHours(1))
    .build();
```

The container exposes useful endpoints like `getTrustListUrl()` and `getStatusListUrl()` that you can point your verifier at during tests, so you can validate the full chain without any external dependencies.

Under the hood, it runs the same `oid4vc-dev` wallet, so both tools share the same protocol implementation.

## Why Both?

`oid4vc-dev` is for your day-to-day development workflow: decoding tokens, testing flows manually, inspecting traffic. `testcontainers-oid4vc` is for your CI pipeline: automated, reproducible integration tests that verify your OID4VP/OID4VCI implementation actually works.

Together, they cover the two biggest gaps I kept running into: "what does this credential actually contain?" and "does my implementation work end-to-end?"

Both projects are open source (Apache 2.0) and available on GitHub:

- [oid4vc-dev](https://github.com/dominikschlosser/oid4vc-dev)
- [testcontainers-oid4vc](https://github.com/dominikschlosser/testcontainers-oid4vc)
