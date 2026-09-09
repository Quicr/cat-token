# Test vectors: generation, draft embedding, and drift detection

`cat-token` owns the reference test vectors for `draft-ietf-moq-c4m`
Appendix A. The vectors are re-derived from a fixed set of keys and
timestamps on every generator invocation, so any change to the wire
encoding surfaces as a diff against the previous run rather than
requiring a human to eyeball hex.

The `generate-test-vectors` binary has three modes:

| Mode                   | Command                                                         | What it writes                                |
|------------------------|-----------------------------------------------------------------|-----------------------------------------------|
| Emit JSON (default)    | `cargo run --bin generate-test-vectors --features moqt`         | `tests/test_data/*.json` (per-category + combined) |
| Emit draft markdown    | `cargo run --bin generate-test-vectors --features moqt -- --emit draft-md [--out PATH]` | Appendix-A-shaped markdown (default: `tests/test_data/draft_appendix_a.md`) |
| Verify against draft   | `cargo run --bin generate-test-vectors --features moqt -- --verify [--from URL \| --from-file PATH]` | exit-code diff; stdout summary; stderr details |

All three modes use identical vector generation code — the emit and
verify modes are pure formatters over the same in-memory tree.

## Determinism

The generator is fully deterministic:

- HMAC key, ES256 private key, and ES256 public point are fixed
  hex constants in `src/bin/generate_test_vectors.rs`
- `iat = 1700000000`, `exp = 1700086400`, `nbf = 1700000000`
- ES256 signatures use RFC 6979 deterministic ECDSA
- HMAC and payload CBOR are canonical-form encoded

The same generator run on a different host must produce byte-identical
output. If a run diffs against a checked-in `tests/test_data/*.json`,
that is a wire-format change — either intentional (a new feature) or a
regression, and either way it needs to be understood before landing.

## Draft embedding: why the emitter exists

Historically, vector blocks were hand-copied from `tests/test_data/*.json`
into `draft-ietf-moq-c4m.md`. The paste pipeline introduced a class of
defects that no unit test catches:

- Mid-hex whitespace inserted at the wrap boundary (e.g.
  `...5820353668 6cfff58bbafc...`)
- Truncation on odd-length hex (`... 582 00ce ...`)
- Byte-string vs text-string tag mismatch (`0x46` vs `0x66`) when a
  reviewer "cleaned up" the JSON while pasting
- Silent drift when only some fields on a vector are updated

`--emit draft-md` sidesteps all of these by keeping every hex-shaped
field on a single line inside its fenced `~~~ json` block. The
recognised hex fields are:

```
cose_hex, payload_cbor_hex, header_cbor_hex, tag_hex,
signature_hex, cnf_jkt_hex, key_hex,
public_key_x_hex, public_key_y_hex, private_key_hex
```

Anything on this list is emitted single-line regardless of length. The
output is intended to be pasted verbatim into the draft. Do not
hand-edit; regenerate the block instead.

## Drift verification

`--verify` fetches a `draft-ietf-moq-c4m.md` copy (`--from URL`, which
defaults to
`https://raw.githubusercontent.com/moq-wg/CAT-4-MOQT/main/draft-ietf-moq-c4m.md`
via a shelled-out `curl`, or `--from-file PATH` for offline runs),
walks the Appendix A JSON blocks, unwraps line-continued string
literals (RFC 7159 forbids raw newlines inside strings but the draft
wraps long hex across lines with leading indent), and diffs each
vector's hex fields against what cat.rs currently emits.

The comparison strips interior whitespace inside hex strings before
comparing, so a hand-wrapped block in the draft still verifies as long
as the underlying bytes agree.

Exit codes:

- `0` — every hex field on every named vector in the draft matches
  cat.rs. Vectors that the draft omits are reported as `MISSING` but
  do not fail verification (the draft may legitimately ship a subset).
- `1` — at least one hex field mismatch or JSON parse error.
- `2` — the draft could not be loaded (network failure, missing file).

Example, run against a local checkout:

```bash
cargo run --bin generate-test-vectors --features moqt -- \
  --verify --from-file /path/to/CAT-4-MOQT/draft-ietf-moq-c4m.md
```

Example, run against the live `main`:

```bash
cargo run --bin generate-test-vectors --features moqt -- --verify
```

## CI gate

`.github/workflows/ci.yml` has a `draft-vectors` job with two steps:

1. **Strict self-verify.** Emit the appendix and verify the emitter's
   own output. A failure here indicates an emitter regression (wrapping
   logic broken, hex fields dropped, JSON malformed) and blocks merge.
2. **Advisory drift check** against `draft-ietf-moq-c4m` on `main`
   (`continue-on-error: true`). A failure here means cat.rs and the
   draft have diverged; the failure is the signal that the draft
   needs a refresh from the emitter output. It does not block merge
   because cat.rs is the source of truth.

## Workflow: updating the draft after a cat.rs change

1. Land the encoding change in cat.rs. Regenerate the JSON fixtures
   with `cargo run --bin generate-test-vectors --features moqt`.
   `tests/test_vectors.rs` will pick up the new bytes and re-verify
   round-trip.
2. Emit the appendix-shaped markdown:
   `cargo run --bin generate-test-vectors --features moqt -- --emit draft-md`.
3. Copy the fenced blocks under `## CBOR Encoding of Claims`,
   `## Token Structure`, `## DPoP Binding`, `## MOQT Authorization Scopes`,
   `## Validation Vectors`, and `## Composite Claims` from
   `tests/test_data/draft_appendix_a.md` into the corresponding
   sections of `draft-ietf-moq-c4m.md`.
4. Run `--verify --from-file /path/to/draft-ietf-moq-c4m.md` on the
   local draft copy; a `mismatches=0` exit is what to look for. The
   advisory CI step will confirm the same against the live draft
   once the draft PR merges.

## Recognised vectors

The generator produces six category files. Every vector carries a
stable `id`; the draft references vectors by that id, so renaming an
id is a breaking change to the interoperability contract.

- `cbor_encoding`: minimal payload-only vectors covering individual
  claim types (iss, aud, exp, nbf, cti, catv, catu, catm, cath,
  catalpn, catnip, catgeo\*, catreplay, catpor, cattpk, cnf).
- `token_structure`: full COSE_Mac0 (tag 17) and COSE_Sign1 (tag 18)
  round-trip vectors with signature/tag verification, using the fixed
  HMAC and ES256 keys.
- `moqt_scopes`: MOQT scope encoding and authorization matching for
  publisher/subscriber/admin/read-only roles and multi-scope tokens.
- `validation`: expected-pass and expected-fail authorization
  scenarios (wrong issuer, wrong audience, expired, not-yet-valid,
  tampered signature, wrong key, algorithm mismatch).
- `dpop_binding`: CAT tokens with `cnf` JWK-thumbprint binding and
  `catdpop` (`window`, `honor_jti`) settings.
- `composite_claims`: OR / AND / NOR / nested operators per
  `draft-lemmons-cose-composite-claims-02`.
