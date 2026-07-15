---
layout: default
title: "Cloud-Native Keycloak: Zero-Downtime Deployments in Practice"
date: 2026-07-15
---

# Cloud-Native Keycloak: Zero-Downtime Deployments in Practice

Keycloak has a reputation for being stateful and delicate to operate. Sessions live in a cache
cluster, configuration lives in a database that people edit through a web console, and a rolling
restart can log users out. None of that has to be true anymore.

This post looks at what "cloud native" and "zero downtime" concretely mean for an identity
provider, why classic Keycloak setups struggle with both, and what the options look like today.
That includes the newest additions in Keycloak 26.7.0 (most prominently the `stateless` feature)
and a set of experimental storage extensions. One combination of those extensions has been running
in a large production environment for over two years (10 million users, about 1 million logins per
day, multiple deployments per day, no deployment downtime).

Everything shown here can be tried locally. The companion repository
[cloud-native-keycloak](https://github.com/dominikschlosser/cloud-native-keycloak) contains eight
runnable scenarios on a local kind cluster.

## What "cloud native" means here

The term is vague, so here is the concrete checklist this post works with:

- **Instances are disposable.** Any pod can be killed at any time without data loss. Kubernetes
  replaces it and nobody notices.
- **Configuration is declarative and version controlled.** Realms, clients, scopes and flows live
  in git. The running system can be reproduced from the repository.
- **Changes ship like code.** A config change is a commit, gets reviewed, and rolls out through
  the same pipeline as an image update. Rollback is a revert.
- **No hand-fed infrastructure.** Nothing in the setup needs manual care during a deployment (no
  cache cluster that has to be drained, no import job that has to be babysat).

## What "zero-downtime deployment" means here

During a rollout (config change or version upgrade, several times a day):

- Users with active sessions stay logged in.
- New logins keep working while pods are being replaced.
- Token refresh and validation keep working.
- No maintenance window, ever.

## Why this is hard with Keycloak

### Runtime state

Keycloak keeps sessions and other runtime state in embedded Infinispan caches. In the classic
setup those caches are replicated between the instances, so the instances form a cluster:

```
        ┌────────────┐        ┌────────────┐
Users ─►│ Keycloak 1 │◄──────►│ Keycloak 2 │   replicated caches
        └─────┬──────┘        └──────┬─────┘   (sessions, cluster membership)
              │                      │
              └─────────┬────────────┘
                        ▼
                  ┌──────────┐
                  │ Database │   config, users
                  └──────────┘
```

Rolling restarts put stress on exactly this design. Pods leave and join the cluster, caches
rebalance, and if things go wrong sessions are lost mid-deployment. Multi-site setups additionally
required an external Infinispan cluster (one more stateful system to operate, upgrade, and keep in
sync with the Keycloak version).

Service meshes add another failure mode. Cluster discovery and cache replication use JGroups
traffic between pods, which a mesh like Istio does not treat as ordinary application traffic. In
an environment with a `DENY_ALL` authorization policy (the setup described later in this post ran
into exactly that), the instances cannot form a cluster at all until the JGroups ports are
explicitly excluded or allowed in the mesh configuration.

### Configuration

Realms, clients, scopes and authentication flows live in the database and are edited through the
admin console. That is convenient and it defeats the checklist above: the live system drifts away
from anything written down, there is no review and no rollback.

The usual answer is config as code through the Admin REST API (v1). Tools like
[keycloak-config-cli](https://github.com/adorsys/keycloak-config-cli) and the
[Terraform provider](https://registry.terraform.io/providers/keycloak/keycloak/latest) take this
route. It works, with a structural catch: the v1 API was built for the admin console, so these
tools re-sync state through an interface that does not diff finely. Re-applying config can delete
and recreate resources. Authentication flows are the classic victim (see
[keycloak-config-cli#875](https://github.com/adorsys/keycloak-config-cli/issues/875)).

## What Keycloak ships today

### Sessions in the database

Since Keycloak 26, user and client sessions are persisted in the database by default (the
`persistent-user-sessions` feature). A restarted pod no longer means lost sessions. This was the
first big step away from cache-resident state.

### The stateless feature (new in 26.7.0)

Keycloak 26.7.0 introduces the `stateless` feature (preview), described in the release notes as
multi-cluster high availability without external caches. It removes the external Infinispan
requirement entirely. Instances keep only local embedded caches and treat the database as the
single source of truth for all state:

```
        ┌────────────┐        ┌────────────┐
Users ─►│ Keycloak 1 │◄┄┄┄┄┄┄►│ Keycloak 2 │   local caches, invalidation
        └─────┬──────┘        └──────┬─────┘   messages only
              │                      │
              └─────────┬────────────┘
                        ▼
                  ┌──────────┐
                  │ Database │   config, users, sessions
                  └──────────┘
```

For deployments this changes the picture fundamentally. Session and auth state no longer lives in
the caches, so nothing needs to rebalance when pods come and go, and losing a pod cannot lose
logins. Replacing all instances one by one becomes an ordinary rolling update. External Infinispan
disappears from multi-site architectures entirely.

One thing survives, though, and it matters for service mesh environments: realm and client config
is still cached per instance, and the instances still form an embedded Infinispan cluster to
invalidate those caches. `stateless` removes the external Infinispan while the embedded clustering
stays, so the JGroups and Istio considerations above apply unchanged.

Two limits are worth knowing for multi-site setups. The
[multi-cluster v2 blueprint](https://www.keycloak.org/high-availability/multi-cluster-v2/concepts)
(also preview) is designed active-active and requires a database that is synchronously replicated
across the sites. And across clusters the config caches invalidate through a database outbox table (polled
every 100ms by default), so a config change becomes visible on the other cluster only after the
next poll.

The storage extensions further down drop that embedded clustering as well.

### Declarative config from the operator and Admin API v2

The [Keycloak Operator](https://www.keycloak.org/guides#operator) has long supported importing a
version-controlled realm through the `KeycloakRealmImport` CR (which goes through the v1 API).

New in 26.7.0 is the Admin API v2 (experimental), built for automation from the start: strict
validation, declarative configuration, and an accurate OpenAPI specification. The operator uses it
to manage clients as individual Kubernetes resources through `KeycloakOIDCClient` and
`KeycloakSAMLClient` CRs:

```yaml
apiVersion: k8s.keycloak.org/v2alpha1
kind: KeycloakOIDCClient
metadata:
  name: demo-oidc-app
spec:
  keycloakCRName: keycloak
  realm: demo
  client:
    enabled: true
    loginFlows: [STANDARD]
    redirectUris:
      - https://demo-oidc-app.example.com/*
```

The client is the CR. The operator reconciles that one resource instead of re-importing a whole
realm. Clients are the first resource type covered, making them the first piece of Keycloak
configuration that official tooling manages outside v1 semantics.

Potential problems apply here too:

- The realm import only creates realms. Updates and deletes are documented as unsupported, so
  ongoing realm changes still need the v1 tools above or the admin console.
- The client CRs define their own schema (the same applies to the Terraform provider), and such
  schemas cover a subset of what Keycloak can actually do. A setting missing from the schema
  cannot be managed through the tool until someone adds it. Of the tools that manage config
  through the admin API, only keycloak-config-cli speaks Keycloak's own realm representation and
  covers the full config surface (realms and everything in them: clients, roles, scopes, flows,
  identity providers). The storage extensions further down sidestep the question (they serve
  Keycloak's own config entities directly, so there is no separate schema to lag behind).

So with stock Keycloak 26.7.0 plus the operator, the checklist looks like this:

- ✅ Instances are disposable (with `stateless`)
- ✅ Sessions survive rollouts
- ⚠️ Config in git (clients reconcile from their CRs, the realm import covers creation only, so
  later realm changes need one of the v1 tools)
- ⚠️ Config changes without v1 re-sync risk (clients only so far, within the client CR schema)

## Going further: swapping the storage layer (experimental)

Keycloak's datastore SPI allows replacing the storage layer entirely. A useful mental model splits
the stored data in two:

- **Config entities**: realms, clients, scopes, roles, flows. Low volume, changed by developers,
  belongs in git.
- **Dynamic entities**: users, sessions, tokens. High volume, changed by end users, belongs in a
  database built for that load.

Three extensions serve these areas from different backends. All three are **experimental** and not
supported by the Keycloak project:

- [keycloak-extension-filestore](https://github.com/dominikschlosser/keycloak-extension-filestore)
  serves the config entities directly from YAML files.
- [keycloak-cassandra-extension](https://github.com/opdt/keycloak-cassandra-extension) serves the
  dynamic entities from Apache Cassandra.
- [keycloak-k8store](https://github.com/dominikschlosser/keycloak-k8store) serves the config
  entities from Kubernetes custom resources.

These setups run without cache clustering entirely: config is served per pod, the
coherency-sensitive caches are disabled, and no JGroups traffic remains (which also ends the
service mesh troubles from the beginning of this post). Current versions of the extensions
activate through the `stateless` feature.

### What config outside the database buys

Drift and re-sync were covered above. Taking config out of the database entirely adds a few more
properties:

- **Config deploys like everything else.** The config is part of the deployment (YAML files from
  ConfigMaps or an image layer, or k8store CRs), so config changes and version upgrades roll out
  and roll back through the same mechanism as the workload itself, applied by the same pipeline.
- **No import step for new environments.** Reproducing an environment from git also works with the
  admin API tools (run the import against a fresh instance). Without a config database that step
  disappears: pods start and the config is there, with nothing to seed and no import to sequence
  into the rollout. Config needs no backup (git holds it), only the dynamic data does.
- **Git history as the audit trail.** In read-only mode nothing can change config outside git, so
  the repository history is a complete record of who changed what, when, and who reviewed it.
- **Smaller attack surface.** In read-only mode there is no write path for config in production.
  A compromised admin account cannot persist config changes.

### A production data point

Experimental labels deserve skepticism, so here is the counterweight. The combination of filestore
(config) and the Cassandra extension (dynamic data) has been running in one large production
installation for over two years:

- 10 million users
- about 1 million logins per day
- multiple deployments per day
- no deployment downtime in that period

Those two years predate the `stateless` feature. The same architecture ran on hand-maintained
cache and feature overrides, which the feature now replaces with a single flag.

Two decisions shaped that architecture.

**Why Cassandra.** The environment is a private cloud spanning two datacenters, operated
active-active. Databases that need a majority quorum are a structural problem with exactly two
sites (when one site is down or unreachable, no majority exists and writes stop without manual
intervention). Cassandra replicates per datacenter and serves local-quorum reads and writes in
each site, so either datacenter keeps working alone. The stateless multi-cluster blueprint above
would hit the same wall in this topology (it assumes a synchronously replicated database across
the sites). The Cassandra extension does not have that requirement: it replaces Infinispan
entirely, sessions are just rows, and they replicate like everything else. Cassandra was also
already established in that environment, which made it the pragmatic choice over introducing a
new database.

**Why filestore.** Keycloak once prototyped a new storage layer (the map storage), including a
file-based store. The project dropped the effort, and the filestore extension forked that
prototype and kept it alive. It replaced a keycloak-config-cli based setup in this environment,
which had run into the v1 re-sync problems described above (auth flow updates corrupting the
database were the breaking point). The filestore removes the import step entirely: the YAML files
**are** the store. Keycloak reads config straight from them, so there is nothing to re-sync,
nothing to drift, and a config rollback is a git revert.

Every update flows through git and [Argo CD](https://argo-cd.readthedocs.io/). A Keycloak version
upgrade, a new client, a changed authentication flow: each is a commit, and Argo CD rolls it out
as an ordinary deployment.

```
                    ┌─────────┐
      git repo ────►│ Argo CD │    every change is a commit
                    └────┬────┘
             ┌───────────┴───────────┐
             ▼                       ▼
     Datacenter 1              Datacenter 2
   ┌────────────────┐        ┌────────────────┐
   │ Keycloak pods  │        │ Keycloak pods  │
   │ (config from   │        │ (config from   │
   │  YAML files)   │        │  YAML files)   │
   └───────┬────────┘        └───────┬────────┘
           ▼                         ▼
   ┌────────────────┐        ┌────────────────┐
   │ Cassandra DC1  │◄──────►│ Cassandra DC2  │   users, sessions
   └────────────────┘  repl. └────────────────┘
```

The trade-off is real and should be stated plainly: this runs outside the supported Keycloak
storage, and features tied to the standard storage (Organizations, for example) are unavailable.
In exchange, config becomes immutable input instead of mutable database state, and the dynamic
store matches the datacenter topology.

### k8store: the next experiment

[keycloak-k8store](https://github.com/dominikschlosser/keycloak-k8store) is a new experiment that
evolves the filestore idea one step further. Instead of YAML files mounted into the pods, config
entities become Kubernetes custom resources:

```
$ kubectl get keycloakclients
NAME                            AGE
demo.demo-app                   2d
master.account-console          2d
master.admin-cli                2d
master.master-realm             2d
master.security-admin-console   2d
```

Each resource carries the full client definition and can be inspected with standard `kubectl`
commands (output trimmed):

```
$ kubectl get keycloakclient demo.demo-app -oyaml
apiVersion: k8store.dominikschlosser.github.io/v1alpha1
kind: KeycloakClient
metadata:
  name: demo.demo-app
  labels:
    k8store.dominikschlosser.github.io/realm: demo
spec:
  realm: demo
  clientId: demo-app
  enabled: true
  protocol: openid-connect
  publicClient: false
  standardFlowEnabled: true
  redirectUris:
    - https://demo-app.example.com/*
  webOrigins:
    - +
  defaultClientScopes:
    - profile
    - email
    - roles
```

The appeal is that config joins the native Kubernetes toolchain. Argo CD diffs and syncs each
client or realm as an individual resource, `kubectl` inspects them, and Kubernetes RBAC governs
who may change what. It also opens up every management style at once: YAML files applied from
git, `kubectl` edits, API calls against the Kubernetes API, and the admin console (every change
lands in the same CRs).

Config updates are pushed instead of polled. Every pod keeps a watch-synchronized in-memory
mirror of the CRs, so a change reaches every instance with the latency of a Kubernetes watch event
(no pod restart, no outbox polling, no cache invalidation round trip).

Because the CRs live in the Kubernetes API instead of per-pod files, write mode works with any
number of instances running. That suits dev environments: click a realm together in the admin
console (with the UI effectively generating the config), then export the CRs to git and promote
them to environments running in read-only mode, where the CRs are authoritative and the console
cannot introduce drift. Like the others, it is experimental.

## Trying it all locally

The [cloud-native-keycloak](https://github.com/dominikschlosser/cloud-native-keycloak) repository
deploys every approach from this post into a local kind cluster, one scenario at a time:

| Scenario | Config store | Dynamic store |
|---|---|---|
| operator + stateless | PostgreSQL | PostgreSQL |
| terraform | PostgreSQL | PostgreSQL |
| keycloak-config-cli | PostgreSQL | PostgreSQL |
| k8store | Kubernetes CRs | PostgreSQL or Cassandra |
| filestore | YAML files | PostgreSQL or Cassandra |
| Argo CD demo | Kubernetes CRs | PostgreSQL |

Each scenario has a fresh variant and a preconfigured variant with a version-controlled demo
realm, plus verification scripts that exercise a real browser login and check availability during
a rolling restart.

## Picking an approach

- **Stock Keycloak + operator + `stateless`** is the supported path. Full feature set (including
  Organizations), sessions in the database, no external Infinispan, clients already declarative
  through Admin API v2. Realm-level config still goes through v1 imports for now.
- **filestore/Cassandra** fits when config must be immutable versioned input, when v1 re-sync risk
  is unacceptable, or when the database topology (two-site active-active) rules out
  quorum-based databases. Experimental status and the feature trade-offs apply. Two years of
  large-scale production operation show that the approach holds up.
- **k8store** takes the filestore approach one step further and stores config as Kubernetes
  resources. It is the youngest of the three extensions and best suited for experiments, without
  a production track record yet.

The direction across all of them is the same. Keycloak is steadily shedding the properties that
made it hard to run cloud-natively, and with 26.7.0 (sessions in the datastore via `stateless`,
declarative clients via Admin API v2) the supported path has moved a lot closer to the checklist
at the top of this post.
