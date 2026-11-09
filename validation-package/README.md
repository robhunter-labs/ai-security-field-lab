# validation-package

**Status: Built, not exercised.** A small companion to the essay [*Proof Outside the Model*](https://robhunterworks.com/writing/proof-outside-the-model/). It has only been run against the synthetic fixtures in this folder. It has not seen a real tool's output, a real target or a real review queue.

The idea it tries to make concrete is one rule:

> A filter may lower a candidate's rank or change where it goes, but only an oracle may close it.

"Blocked by the WAF", "unreachable", "duplicate", "intentionally public" and "internal only" are states with a re-test condition, not verdicts. This folder holds a schema for the minimum validation package, a catalog of the ways a tool's candidate can be non-unique, untrue or not actionable, and a checker that refuses records which break the rule.

## What it is, and what it isn't

| It is | It isn't |
|---|---|
| A schema for a minimum validation package and for reason-coded candidate states | A scanner, a triage platform or a replacement for a person's judgment |
| A checker that **refuses** records that break the rules, with a reason for each refusal | A decision-maker. It never says "vulnerable" or "safe"; it says "this record can't close yet, and here's why" |
| A catalog of 103 classes of non-unique, untrue or non-actionable candidates, kept as data and rendered to Markdown | A measured result. Tiers outside the panel picks are my own assignment |
| 30 synthetic fixtures, each with an expected verdict | Evidence that any of this works on real traffic. Every host is under `.test` and every address is from a documentation range |
| A generator for a one-page developer retest card | A way to replay anything automatically. Nothing here sends a request |

Standard-library Python 3 only. No network access, no dependencies.

## Layout

```
validation-package/
  check_package.py          checker: packages, state transitions, claim key, grouping, fixtures runner
  schema/
    package.schema.json         minimum validation package (draft 2020-12)
    candidate_state.schema.json reason-coded candidate states
  catalog/
    classes.json                single source of truth (103 classes, 16 families, 5 proposed additions)
    build_catalog.py            renders the Markdown; --check fails if it is stale
    NON_UNIQUE_CLASSES.md       generated catalog
    CATALOG_SOURCE_CHECK.md     how each source was checked against the classes that cite it
  fixtures/
    _base/package_high_idor.json  a complete High package; package fixtures patch it (RFC 7386 merge patch)
    01..30_*.json                 synthetic cases, each with an "expected" block
  replay/
    make_card.py                one-page retest card (curl.exe, Invoke-RestMethod, stdlib Python)
    examples/RETEST_CARD_VP-0001.md
  tests/test_fixtures.py        unittest: every fixture, plus claim key, grouping, card and catalog checks
```

## How to run it

```bash
git clone https://github.com/robhunter-labs/ai-security-field-lab.git
cd ai-security-field-lab/validation-package

python3 -m unittest discover -s tests -v          # run everything
python3 check_package.py fixtures/*.json          # PASS/FAIL per fixture
python3 check_package.py my_package.json          # check one package; exit 1 on REFUSE
python3 check_package.py my_package.json --json   # machine-readable result
python3 check_package.py --claim-key "https://api.example.test/v2/orders/48213?b=1&a=2" \
    --auth user --sink object-read --param path:order_id
python3 replay/make_card.py fixtures/_base/package_high_idor.json -o card.md
python3 catalog/build_catalog.py                  # after editing catalog/classes.json
```

A result looks like this:

```
fixtures/11_callback_blocked_by_egress_must_not_close.json  (via --json, abridged)
  verdict: REFUSE
  POSITIVE_CONTROL_DID_NOT_FIRE: the positive control ran but did not fire, so the oracle
    could not have fired either (for example egress is blocked ...). Its silence proves nothing.
  labels: NO_CALLBACK, EGRESS_UNVERIFIED
  suggested state: demoted (EGRESS_UNVERIFIED, recheck in 14 days)
```

## The rules it enforces

| Rule | Refusal code | Fixture |
|---|---|---|
| A close needs an oracle other than "none" | `CLOSE_WITHOUT_ORACLE` | 28 |
| A close needs a positive control that ran and fired | `CLOSE_WITHOUT_POSITIVE_CONTROL`, `POSITIVE_CONTROL_DID_NOT_FIRE` | 27, 11 |
| "Blocked at edge" is never "not vulnerable" | `EDGE_RECORDED_AS_NOT_VULNERABLE` | 01 (02 shows the accepted state) |
| No merge across auth level, route, middleware or parameter | `NEVER_MERGE_AXIS` | 18 (19 shows an accepted merge) |
| No merge that drops a chain step | `MERGE_DROPS_CHAIN_STEP` | 20 |
| An off-origin redirect is a scope question, not a duplicate | `OFF_ORIGIN_REDIRECT_IS_SCOPE_QUESTION` | 07 |
| A demotion needs a reason code and a recheck date | `DEMOTION_WITHOUT_REASON`, `DEMOTION_WITHOUT_RECHECK` | 24 |
| A demotion reason must be backed by the detector it names | `REASON_NOT_SUPPORTED_BY_EVIDENCE` | 05, 10 (04, 06, 09 accepted) |
| A downgrade is not signed by its own author | `SELF_SIGNED_DOWNGRADE` | 22 |
| Critical needs a direct oracle, an independent replay, reachability and proven impact; otherwise "High, pending" | `CRITICAL_GATE` | 21 |
| For High and Critical, the expected difference is recorded before replay | `PREREG_AFTER_REPLAY` | 25 |
| A handoff replay that needs tester tooling is marked tester-assisted | `HANDOFF_NEEDS_TESTER_MARK` | 26 |
| A changed target is re-baselined, not closed | `TARGET_CHANGED` | 23 |
| A cached response can't support a close | `CACHE_ARTIFACT_UNCONTROLLED` | 03 |
| Out-of-band confirmation needs an HTTP callback attributed to the target | `CALLBACK_DNS_ONLY`, `CALLBACK_FROM_INTERMEDIARY` | 12, 14 (13 accepted) |
| Timing confirmation needs 30+ baseline samples, interleaved controls and dose-response | `TIMING_INSUFFICIENT` | 15 (16 accepted) |
| Credentials are referenced by role, never inlined | `INLINE_CREDENTIAL` | 30 |

Grouping fixtures 08 (alias host versus a stranger on the same CDN IP) and 17 (a vended product grouped by version, with an unowned group routed rather than dropped) check that every candidate lands in exactly one group with its lineage.

The checker also refuses a few things no fixture targets yet: a CVSS v4 vector whose metric groups don't match its label (B, BT, BE, BTE), a replay outside the authorized window, a header that names an identity role with no credential reference, and a retest with no observations recorded.

## Limits

These are the ones I know about. There are surely others.

- **Synthetic only.** The fixtures were written alongside the checker, so passing them shows the code does what I meant, not that what I meant is right. The real test is a tool's own export against a known answer key (see `ROADMAP.md`).
- **Heuristic detectors.** Edge detection knows two vendor headers plus any block-page hashes you supply. Login detection is a path and title pattern. Soft-404 matching needs two calibration probes and exact word and line counts. The edge-wording check on dismissal reasons is a keyword match and will misfire on phrases like "blocked by input validation".
- **The claim key is a starting point.** It replaces numeric and UUID path segments only. Hex IDs, slugs and dates are not normalized, so it over-splits some routes, and a numeric segment that isn't an ID (a year, a version) is over-merged. Keeping the parameter as a never-merge axis means per-parameter explosions (catalog A12) stay separate on purpose.
- **Self-declared fields.** Signers, "proven" versus "inferred", and pre-registration timestamps are taken as written. Nothing verifies who signed or when. Self-signing is caught only when the same name appears twice.
- **Attribution depends on context you supply.** Callback attribution needs the target's egress ranges and a list of intermediary networks; alias detection needs a back-end fingerprint you computed elsewhere.
- **Partial JSON Schema.** The built-in validator covers the subset these schemas use. It isn't a general validator.
- **No CVSS scoring.** The vector is checked for shape and nomenclature, not scored, and its rating isn't checked against the vector.
- **The retest card is single-request.** Multi-step flows, cookies and CSRF tokens aren't handled. Generated commands do not follow redirects; a redirect requires a fresh scope check before replaying its destination.

## Where it came from

The catalog's source keys come from the research note it was built from. Every source was opened again on 2026-11-08 and checked against each class that cites it; keys a page did not support were removed. 43 of the 103 classes rest on reasoning alone and are marked that way. `catalog/CATALOG_SOURCE_CHECK.md` records each decision, and the generated Markdown lists every source. The seven panel picks are the classes where three AI review passes, reading as an audience editor, a senior practitioner, and an AI tool builder, converged; I kept the tiers they assigned. No other person reviewed the selection. Signing tiers as properties of a validation route would live in a separate `ROUTES.md`; it isn't written yet.

Feedback and counter-examples are welcome, especially a fixture the checker gets wrong.
