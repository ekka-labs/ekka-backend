# ekka-backend

> EKKA governs desk administration from request to execution. Only
> organization admins can request changes. Govern signs the authorization, and
> the customer's adapter verifies it and enforces the approved limits.
> Credentials remain in the customer's Enclave vault.

This repository is "the customer's adapter" in that statement: the EKKA desk
backend adapter. NVIDIA OpenShell is the desk backend this adapter supports
today. The adapter runs beside it, on the customer's machine. The Enclave's API gate calls it over a Unix socket.
For each call it verifies the Govern-signed gate token, enforces the limits on
the organization's grant, and only then makes the change on the desk backend.
Its protocol is `ekka.backend.v1`; the contract files it implements are
vendored under [`vendor/contracts/`](vendor/contracts/).

```bash
$ ekka-backend --version
ekka-backend 0.1.0 (contract ekka.backend.v1)
$ ekka-backend serve --config /etc/ekka-backend/config.json
```

`serve` loads the config (refused unless it is a regular file this user or root
owns, writable by no one else, with no unknown key), logs its digest and the
Govern key ids, and listens on the contract's socket. It answers the contract's
routes, each in the contract's closed shape. Every call's gate token is verified
and the grant's limits are checked before the desk backend is called, and every
operation in the table below runs on the desk backend. Every change is recorded
before anything reaches the desk backend, and a redelivered change is answered
from its record. A change still running, even after a restart, is finished by
the next call for its desk (see "Recovery" below).

## What the adapter never holds

Each line is enforced in this repository's code, named in brackets.

- **No stored credential.** The configuration holds none. The adapter's
  credential (the client secret of the Enclave's `desks` connection) stays in
  the customer's Enclave vault. The Enclave's API gate adds it to each call as
  `Authorization: Bearer`, and the adapter holds it for that call only. It is
  zeroed when the call ends, never printed, and cannot be serialized
  (`token::Credential`; tested in `token_tests.rs`).
- **No token on disk.** The adapter signs in to NVIDIA OpenShell's gateway
  with that credential. It keeps ONE desk backend token, in memory only, tied
  to a digest of the credential it came from. A rotated credential gets a new
  token, and a token the desk backend refuses is dropped. Neither the token nor the credential is
  ever logged or put in an error (`signin.rs`).
- **No signing key.** It holds only Govern's PUBLIC keys: one or two Ed25519
  keys, each matched to a token by exact `key_id` (`config.rs`, `token.rs`). It
  can check Govern's signature. It cannot make one.
- **No provider secret.** It reads provider records only as NVIDIA OpenShell
  answers them, with every credential value `REDACTED`. Any other value is
  refused `PROVIDER_CREDENTIAL_NOT_REDACTED`, named by its key, never hashed or
  shown (`providers.rs`; tested in `providers_tests.rs`). It never creates,
  changes or deletes a provider record.
- **Only its own sign-in.** It signs in only as its own client,
  `ekka-desk-admin`, and the configuration is refused if it names any other
  (`config.rs`). That client is NOT powerless: its calls (below) need
  `sandbox:read`, `sandbox:write`, `provider:read` and `config:write`, with the
  administrator role NVIDIA OpenShell's gateway requires for them. It needs
  exactly those, never `provider:write` or `openshell:all`. It never holds the
  desk backend's bootstrap administrator or the sign-in service's admin
  password.
- **No way into a desk.** Its desk backend client has ten calls and no more:
  five reads (a desk, its policy status, a provider, a provider profile, the
  profile list) and five changes (create, delete, stop or start, set policy,
  detach a provider). It has no call that runs a command in a desk, opens a
  shell, or moves a file in or out (`gateway.rs`).
- **One record per change, and nothing else on disk.** Each change is written
  to `<state_dir>/operations/<request id>.json` (mode 0600, in a folder only the
  adapter's user can open) before it reaches the desk backend. The record holds the
  request, its digest, when it was admitted, its answer, and the Govern-signed
  gate token for that one operation, re-checked before recovery re-issues it.
  Never the credential, and never the desk backend token (`store.rs`). Beside the
  records, `<state_dir>/running/<request id>`, an empty file, names each change
  still running.
- **Two files it reads that the installer writes.** A settle marker,
  `<state_dir>/settle/<request id>.json`, and a settle hold,
  `<state_dir>/settle/<request id>.hold`, each owned by the adapter's user,
  mode 0600. When a marker settles its change the adapter renames both
  `.used` (`recover.rs`). Neither holds a secret.
- **Every call it makes has a time limit.** The desk backend: 10 s to connect,
  30 s per call (`gateway.rs`). The sign-in service, discovery and token: 10 s
  (`signin.rs`). The Enclave's claim socket: 10 s (`claims.rs`). None can hang
  a desk call.
- **Logs name, never carry.** A call is logged by its token id, run id,
  operation id, route, outcome and refusal code (`server.rs`).

### Limits

- **A read's token, after a restart.** Each gate token is used once. For a
  CHANGE, the record decides: a change whose record exists is answered from it,
  never run again, even after a restart (`ops.rs`, `store.rs`). For the two
  READS (`status`, `policy_get`), the adapter remembers used tokens in memory
  only, until each one expires (`token.rs`). A restart forgets that list, so
  within its lifetime a read's token could be presented again after a restart. A
  read changes nothing, and only a caller running as the adapter's own user can
  present it: the socket closes any other peer unanswered (`server.rs`).

## Configuration

One JSON file, written by the installer and mounted read-only. It holds no
credential: the backend's credential arrives with each call.

| Key | Meaning |
|---|---|
| `config_version` | `1` |
| `organization_id` | a token's `tenant_id` must equal it |
| `api_gate_instance` | a token's `scope.instance` must equal it |
| `govern_keys` | 1 or 2 `{key_id, public_key_b64}`; a token's `key_id` must match one exactly |
| `backend_gateway` | `{url, client_id, workspace, issuer, ca_pem_path?}`: the desk backend this adapter administers, and the sign-in service it gets its desk backend token from |
| `deadline_seconds` | default 120; 150 or more is refused |
| `socket_path` | default `/run/ekka-backend/backend.sock`; its directory must be this user's, mode 0700 |
| `state_dir` | default `/var/lib/ekka-backend` |

## Digests for a desk grant's limits

A desk grant's limits hold digests the adapter checks. An installer writes them with
the adapter's own code, from the pinned image, so the two never disagree:

```bash
docker run --rm -i <image> digest policy - < policy.json      # SandboxPolicy, NVIDIA OpenShell proto JSON
docker run --rm -i <image> digest provider - < provider.json  # {"name", "provider", "profile"}
```

One line on stdout (`sha256:<hex>`), exit 0; a refusal is one line on stderr
starting with its code, exit 2.

- **`policy`** (`policy_digests`): the policy decoded as NVIDIA OpenShell's
  `SandboxPolicy`, re-encoded in one fixed form (proto3 JSON names, defaults
  left out, enums by name), then `sha256` over canonical JSON (keys sorted, no
  whitespace). A field the pinned proto does not know is refused.
- **`provider`** (`provider_config_digests`): `sha256` over canonical JSON of
  ONE entry, `{name, type, profile_workspace, config, credential_names,
  profile}`: the name the desk carries the provider under; the record's type,
  profile workspace and non-secret `config` (sorted); the NAMES of its
  credentials (sorted), never a value; and its profile in the same canonical
  form, without `resourceVersion`, `source`, `scope`, `annotations`,
  `displayName`, `description`, `category` and `discovery`. It is exactly one
  entry of the desk-level providers digest the Enclave pins, built the same
  way; a test holds the Enclave's own value for a fixture. The input is `{"name": "...", "provider":
  <Provider proto JSON>, "profile": <ProviderProfile proto JSON>}`, from the
  desk backend's own reads. A credential value other than `REDACTED` is refused
  (`PROVIDER_CREDENTIAL_NOT_REDACTED`), never hashed.

## What a desk grant's limits mean

A desk grant's limits (`governance/grant-constraints/desks.v1` in the
contracts) are checked against every create and policy change before the desk
backend is called. A refusal names the limit. In NVIDIA OpenShell's proto (pin
5a7728c, v0.1.4), the names mean:

| desks.v1 | NVIDIA OpenShell field | Rule |
|---|---|---|
| `image_digests` | `SandboxTemplate.image` | a create's image is `<name>@sha256:<64 hex>` (a registry digest) or `sha256:<64 hex>` alone (a local content ID, Docker's image ID, for an image the machine built), and that digest is listed (`CONSTRAINT_IMAGE_DIGESTS`) |
| `policy_digests` | `SandboxSpec.policy` | a create's policy, in canonical form, has a listed digest (`CONSTRAINT_POLICY_DIGESTS`) |
| `allowed_hosts` | `NetworkEndpoint.host` | every endpoint's host is listed or under a listed `*.` domain, at create and after every change (`CONSTRAINT_ALLOWED_HOSTS`) |
| `policy_baseline.network.allowed_ports` | `NetworkEndpoint.port`, `.ports` | every port is listed; an endpoint with no port reaches every port and is refused (`CONSTRAINT_POLICY_BASELINE`) |
| `policy_baseline.network.allowed_cidrs` | `NetworkEndpoint.allowed_ips` | every address or range is inside a listed IPv4 range; empty means none (`CONSTRAINT_POLICY_BASELINE`) |
| `policy_baseline.network.provider_added` (`listed_only`) | `network_policies` keys `_provider_*` | a caller's policy carries no provider rule; the desk backend adds them, only for attached providers (`FIELD_NOT_ALLOWED`) |
| `policy_baseline.must_equal`: `filesystem` | `SandboxPolicy.filesystem` | byte-equal (canonical JSON) to the baseline: on a change, the desk's creation policy (`CONSTRAINT_POLICY_BASELINE`) |
| `must_equal`: `process` | `SandboxPolicy.process` | as `filesystem` |
| `must_equal`: `enforcement` | `SandboxPolicy.landlock`, `NetworkEndpoint.enforcement` | landlock equal to the baseline, and every endpoint `ENFORCE`: an audited or unset endpoint is refused (`CONSTRAINT_POLICY_BASELINE`) |
| `must_equal`: `user_namespaces`, `driver`, `runtime` | `SandboxTemplate.user_namespaces`, `.driver_config`, `.runtime_class_name` | never set by the adapter, never reachable by a policy change; a resulting desk carrying any of them, or resources, answers `unknown` |
| programs (every rule's `binaries`) | `NetworkBinary.path` | a change names only programs the baseline named, and leaves no rule without programs (which NVIDIA OpenShell reads as any program) unless the baseline had one (`CONSTRAINT_POLICY_BASELINE`) |
| (no desks.v1 name: a fixed rule) | `NetworkEndpoint.credential_binding`, `allow_uninspected_credentials`, `provider_credentialed`, `credential_signing`, `signing_service`, `signing_region`, `token_grant_owner`, `*_credential_rewrite` | a policy change never adds, changes or moves an endpoint carrying a provider's credentials: each one is kept exactly as the creation policy has it (same rule, same programs), or dropped. Changing where a provider's credentials reach is a provider change, made at install, never a policy change (`CONSTRAINT_CREDENTIAL_ENDPOINT`) |
| `providers` | `SandboxSpec.providers` | a create's providers are listed (`CONSTRAINT_PROVIDERS`) |
| `environment_keys` | `SandboxSpec.environment` | every key is listed (`CONSTRAINT_ENVIRONMENT_KEYS`) |
| `repo_hosts` | (none) | unused since contracts 0.65.0: a create carries no `repo` (refused `FIELD_NOT_ALLOWED`); repositories reach a desk through a setup plan |

After the backend answers, the desk it reports is compared with the request
(image, providers, policy digest, no template fields the adapter never sets);
a difference answers `unknown`.

## What each operation does on the desk backend

Every change follows the same order:

1. Sign in with the call's credential.
2. Claim the desk at the Enclave.
3. Make the desk backend call, with the operation's request id as NVIDIA OpenShell's `request_id`.
4. Read the desk back.
5. Write the answer to the operation's record.
6. Only then, release the claim with the outcome and the read-back.

If the record cannot be written (tried twice), the claim is NOT released. The desk stays held, the change answers `running` as its record says, and recovery settles it later. A crash between the record and the release leaves a settled record and a held desk; the operator release (`ekka desk release --operation`) is for exactly that. A read takes no claim.

| Operation | NVIDIA OpenShell calls | Answer |
|---|---|---|
| `create` | CreateSandbox, then GetSandbox and GetSandboxPolicyStatus | `backend_id`, `resource_version`, `policy_digest`, `providers` |
| `delete` | GetSandbox, DeleteSandbox, then GetSandbox until NOT_FOUND | released with `{deleted: true, sandbox_id}` |
| `stop`, `start` | StopSandbox or StartSandbox, then reads until the phase shows | the desk's facts |
| `policy_set` | GetSandbox (the creation policy), UpdateConfig at `expected_resource_version`, then reads until the new revision is loaded | the new `policy_digest` and `resource_version` |
| `provider_detach` | DetachSandboxProvider at `expected_resource_version`, then reads | the remaining `providers`; released with the new `providers_digest` |
| `status` | GetSandbox, GetSandboxPolicyStatus, and each provider's record and profile | the desk's facts and `providers_digest` |
| `policy_get` | GetSandbox, GetSandboxPolicyStatus | `policy_digest` and `resource_version` |

- **A create** carries the label `ekka.ai/desk=true`, the label `ekka.ai/operation=<request id>`, and the annotation `ekka.ai/desk-providers` naming the providers it is made with. The Enclave's auto-registration reads that annotation as the desk's required providers. A person cannot rewrite it later, because people's own desk sign-ins only read. A create sends no command (the image's own) and no `repo`: a create that carries one is refused `FIELD_NOT_ALLOWED`, since nothing on a desk reads it (contracts 0.65.0).
- **A detach** of a provider the desk's agent requires is refused `DESK_PROVIDER_REQUIRED` before the desk backend is called. The list comes from the Enclave's claim answer, never from a label or the request. An Enclave that names no list refuses every detach.
- **A refusal** before the desk backend call releases the claim `refused`: nothing changed.
- **A change whose reply is lost, or that the desk backend holds as `REQUEST_OUTCOME_UNCERTAIN`,** may still finish. It answers `running` (202, with its request id), and its claim is not released, so the desk stays held and no person can release it by hand.
- **A change that completed but whose desk does not match** the request answers `unknown`.

### Recovery

A change still `running` is never finished by the adapter on its own. The next call for its desk, `status` or a change, takes each one first, oldest first (`recover.rs`). A change whose first attempt is still running in the adapter is never taken.

**The host settle procedure** settles one change by hand, on the machine. It is part of the installer, not of this adapter: in the EKKA desks kit it is `up.sh desks settle <desk> --operation <request id>`. Any installer can provide it, because all it does is write two files into the adapter's state directory, and both have a contract schema:

- the settle hold, `settle/<request id>.hold` ([`settle-hold.v1`](vendor/contracts/backend/settle-hold.v1.schema.json)), written BEFORE the procedure restarts the desk backend;
- the settle marker, `settle/<request id>.json` ([`settle-marker.v1`](vendor/contracts/backend/settle-marker.v1.schema.json)), written once the desk's containers have stopped changing.

The adapter takes each running change through these rules, in order:

1. **A change never sent.** Its record names no send: the adapter stopped before the change passed its claim and every check, or the change was refused before sending. It is never re-issued. Nothing reached the desk, so it settles `refused` `NOT_APPLIED`, and its claim, if it holds one, is released. The driver notes each change's first send in its record, durably, after its claim and every check and right before the desk backend call. Not noted means not sent.

2. **A settle marker for it** means the change has stopped. Nothing is sent: the read-back alone decides, `ready` or `unknown`, and the claim is released. The adapter refuses a marker when:
   - it names another operation, desk, backend id or desk backend (`<url>#<workspace>` from the adapter's config, byte for byte);
   - its desk backend restart is not after the change was LAST SENT (its admission, or its latest re-issue). The record notes each send before it goes, so no send can still be inside the desk backend when a marker releases the desk;
   - its quiet window has not ended, or does not end after the restart;
   - it names a container still `created` (never started), `restarting` or `removing`. A container that stays `created` keeps its change running and its desk held until the container starts or is removed; then the desk is settled again;
   - the file is not the adapter's user's, is not mode 0600, or is a link.

   A marker sends nothing, so it needs no stored token: a Govern key rotated since never holds a settled desk.

3. **A create that never reached the desk.** Its marker names no backend id and no container. It is accepted only for a create, and only if the desk backend, asked after its restart, answers that it has no such desk (`NOT_FOUND`; an OK answer with nothing in it is never taken for absent). Then the answer is `refused` `NOT_APPLIED` and the claim is released. The desk backend would find a create it had kept, and nothing is sent after a marker, so that create cannot land later.

4. **Otherwise, unless a settle hold stands, within 20 hours of admission,** the change is re-issued. It is the same request, under its own request id and the claim it already holds. Its stored token is re-checked at its admission time, and a token that no longer verifies is never sent. NVIDIA OpenShell's gateway replays a recorded success, or answers UNCERTAIN, and never applies it twice. It keeps a success for 24 hours; after that the same id would run again, so the adapter stops at 20. A request id the desk backend holds with another payload stays `running`, never `refused`, because something ran under it.

5. **Otherwise it stays `running`.** Only the host settle procedure settles it.

**The settle hold.** While a hold stands, the adapter never re-issues that change, whatever asks. A `status` during the quiet window then sends nothing, so the marker's restart stays after the last send and the marker counts. A hold that is not a regular 0600 file of the adapter's user, or is not exactly `{operation_id, held_at}` for this change, counts as no hold (logged): a hold can only stop sends. If the procedure stops without a marker, the hold stays and the change stays held. Check the desk, then remove the hold with the installer's unhold step (in the EKKA desks kit: `up.sh desks unhold <desk> --operation <request id>`).

A refusal or an answer whose record cannot be written is tried twice; still unwritten, the call answers `running` (the record still says so), and recovery settles it later.

While one stays unresolved, the desk is held. A `status` answers `running` with that change's request id, and a change for that desk is recorded and refused `DESK_BUSY` before anything is sent, even to the Enclave.

## Build

```bash
cargo test --workspace
docker build --platform linux/amd64 -t ekka-backend .
docker run --rm ekka-backend --version
```

The image is a static musl build on `gcr.io/distroless/static-debian12:nonroot`,
both bases pinned by digest in the `Dockerfile`. It has no shell.

## Release

A version tag `vX.Y.Z` that equals `Cargo.toml`'s version runs
`.github/workflows/release.yml`. It pushes `ghcr.io/ekka-labs/ekka-backend:vX.Y.Z`,
signs the digest keyless with Sigstore, attaches an SPDX SBOM attestation, and
verifies both. If signing fails after the push, the image stays in the
registry unsigned, and the checks below refuse it.

## How to verify a release

Use the image by its digest (`@sha256:...`), never by its tag: a tag can be
moved, a digest cannot. Before you run an image, check all three:

1. **It was signed by this repository's release workflow, for a version tag.**

   ```bash
   cosign verify \
     --certificate-identity-regexp '^https://github\.com/ekka-labs/ekka-backend/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     ghcr.io/ekka-labs/ekka-backend@sha256:<digest>
   ```

   A signature from any other workflow, branch or repository fails this check.

2. **Its SBOM is attested by the same workflow.**

   ```bash
   cosign verify-attestation --type spdxjson \
     --certificate-identity-regexp '^https://github\.com/ekka-labs/ekka-backend/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     ghcr.io/ekka-labs/ekka-backend@sha256:<digest>
   ```

3. **It is the version you expect.**

   ```bash
   docker run --rm ghcr.io/ekka-labs/ekka-backend@sha256:<digest> --version
   # ekka-backend X.Y.Z (contract ekka.backend.v1)
   ```

These are the same checks the release workflow runs on the image it has just
pushed.

## License

Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
