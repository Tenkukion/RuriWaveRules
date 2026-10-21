# RuriWaveRules

Public activation authorized on 2026-10-21 for Tenkukion/RuriWaveRules and GitHub
Pages. Actual publication/signature status is proved by the repository and its
signed immutable releases, not by this authorization statement.

Data-only source rules for the RuriWave NativeRule schema 1 interpreter.
The application source, user data, internal reports and build/signing material
do not belong in this repository.

`rules/` contains the sole editable rule documents. `catalog.json` defines stable
IDs, distribution order, compatibility and installation defaults. Its fixed
`bootstrapIds` are exactly the approved twelve: expanding the library does not
expand the application defaults. Never edit generated manifest/bundle by hand.

Validate: `python tools/build_release.py validate`

Regression: `python -B -m unittest discover -s tests -v`.
Validation checks the data-only contract and current retained rules; the private
client's NativeRule interpreter tests additionally validate its generated App
snapshot. This is not a live website availability test.

Prepare an unsigned **local-only** snapshot:
`python tools/build_release.py build --output dist/local --sequence 0 --version local-1 --revision LOCAL_PREPARATION --issued-at 2026-10-21T00:00:00Z --expires-at 2026-10-28T00:00:00Z`

Publishing is a separate explicit workflow, not an ordinary commit. All rule
documents must pass the client interpreter contract before application bundling.
Rules are not executable scripts and cannot grant new browser/network powers.

## Installation contract

- New installations receive the fixed twelve offline; first six on, last six off.
- New library entries require explicit installation. Update never installs them.
- Installed updates preserve enablement. Explicit reinstall adopts the install
  default and clears the deletion exclusion, without duplicate source identity.
- Retirement stops distribution, not local playback, enablement or installation.
- Unknown ownership/local edits are conflicts, never implicitly overwritten.
- Only the installed, still-distributed managed subsequence follows remote order.
- Playback keeps its source-rule snapshot across episode changes; no hot swap.

## Trust, freshness, replacement and recovery

Signed manifests use Ed25519 over the exact UTF-8 payload bytes, carried as
base64 with a pinned key ID. Sequence/version, validity, compatibility, file
hashes and namespace are all inside the signed payload. Hash/TLS alone is not
publisher authentication. Private keys must remain outside Git and artifacts.

Clients reject lower accepted sequences and changed content at the same sequence;
expired/future manifests mean **cannot confirm latest state**, not up-to-date.
Local installed rules continue working when checks fail or expire. Freshness
uses the device clock: a detected backwards clock cannot establish freshness;
this does not claim resistance to replacing the entire local data root.

Rule-content recovery does not reset the accepted version floor. The existing
rule Owner serializes a separate security checkpoint before accepting metadata;
an unreadable checkpoint makes online maintenance fail closed while leaving local
playback available. Restoring .lkg content cannot make an older signed manifest
current. Replacing the entire data root or controlling the device clock/storage
is outside this network replay guarantee. Without a previously observed version,
an unexpired signed older release cannot be distinguished from the newest one;
the validity window bounds this freeze risk, it does not eliminate it.

For a rule recovery, restore reviewed earlier rule content, increase its source
version, then publish a new higher sequence with a new validity window. Never
overwrite an old release or lower the client's accepted floor. The normal user
confirmation applies the repair; website playback errors do not trigger rollback.

Trust-key replacement/recovery uses an explicitly reviewed **client release**:
update the pinned public-key configuration, validate old/new signature rejection
tests, build and accept a new client Candidate, then distribute manifests signed
by the approved key. A compromised key is removed, not remotely self-replaced.
The repository cannot declare its own untrusted key trusted. Keep the prior
working local rules during key rollout. Key creation, storage and workflow
permissions require separate owner approval. No production key is included here.

Executable replacement: after the owner approves the new public-key identity,
prepare a JSON map of approved key IDs to raw 32-byte base64 public keys (never
private keys), then run `python tools/replace_client_trust.py --current <client-trust.json> --approved-public-keys <approved-public-keys.json> --revision <old-plus-one> --output <new-client-trust.json>`.
The command creates a new review artifact, never merges old keys or activates it.
For a normal overlap rollout explicitly list both approved keys; for compromise
recovery explicitly omit the compromised key. Review/replace the client's single
`assets/official-rules/trust.json`, run old/new key acceptance/rejection and replay
tests, then use the separately authorized client Candidate/release process. Keep
the accepted sequence floor: key replacement is not a downgrade exemption. If
the signing key is lost, existing rules continue; a client release can pin a new
approved key without requiring a signature from the lost/compromised key.

Recovery limit: current sequence and source-version representations are bounded.
If an already trusted/compromised publisher exhausts those ranges, the public-key
replacement tool alone cannot repair them. An independently reviewed client
recovery release must extend the representation/acceptance policy for the exact
incident; no remote document is allowed to reset the stored floor. That emergency
client migration is not implemented or claimed by this local preparation.

## Workflow activation (not performed)

Ordinary pushes/PRs run read-only validation only. `publish.yml` is manual and
additionally disabled until the owner sets `RULES_PUBLISH_ENABLED=true` and the
exact `OFFICIAL_RULES_REPOSITORY`. It uses a normal `published` branch commit for
append-only artifacts, uploads the complete `dist/` tree, then the official Pages
deployment action exposes that whole artifact. Never overwrite a release name;
repair with a higher batch sequence and higher changed-rule versions. A failed
deploy can be retried using the already persisted complete artifact.

Before activation approve public content/provenance/license, actual account,
repository/branch push, Pages configuration, signing identity and storage. The
prepared workflow proposes protected `rules-publish` and `github-pages`
environments, minimal job permissions, an encrypted environment secret
`RULES_ED25519_KEY_PEM`, and public `RULES_KEY_ID` / `RULES_PUBLIC_KEY` variables.
Those are configuration requirements, NOT permissions already granted or secrets
created. Public-key bytes must match the independently accepted client pin.
Actions are pinned to official release commits. Private keys only enter a
permission-restricted temporary runner file, never the artifact or Git tree.
Each independently downloadable release carries its recipient MIT notice and,
once the owner chooses it, the root license. Their paths, hashes and sizes are
bound by the signed manifest. Formal signing fails before key use if the root
LICENSE is missing; the file does not replace the separate owner approval gate.

Keep the initial verified twelve-source release snapshot as the explicit App
bootstrap input if a later distribution batch retires one of its members; the
publisher refuses silently substituting another source. The current remote
directory, not that historical bootstrap, determines online installation and
maintenance status. No retired rule is removed from an installed client.

## Rights and public-operation gate

Ruri-authored contributions are MIT licensed by the owner's 2026-10-21 decision.
The three Native configurations moonci/DM84/sorani conservatively retain their
KazumiRules MIT configuration-input notice; conversion is not a clean-room claim.
Other rules use selected public-page/API observations, without copying a client
implementation. This does not grant rights to websites, media or trademarks.
Scoped provenance review and the owner's content/license/account/public-operation
and dedicated-key permissions were obtained before initial activation. These do
not authorize publishing the private client or changing its existing license.
