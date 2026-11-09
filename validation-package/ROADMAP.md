# Roadmap

Status today: **v1, built, not exercised.** Everything below is a plan, not a promise.

## v1.1: make v1 honest about real input

- **Import adapters** for a few common exports (SARIF, Nuclei JSONL, ZAP JSON) into the candidate shape, keeping the tool's own fields as lineage.
- **Configurable ID normalizers** for the claim key: hex and ObjectId segments, dates, slugs from a route map, and an opt-out for numeric segments that aren't IDs.
- **More edge fingerprints**, kept as data, with a test per vendor marker.
- **Signer identities and routes.** A small `ROUTES.md` and a signer registry so "routes up" means a named role, not just a different string. Second review keyed to the finding and route, never to a person's state.
- **Tamper-evident pre-registration.** Hash the expected difference at capture and record the hash before replay, so the timestamp isn't only self-declared.
- **Negative-space ledger report.** Age and sampling floor for demoted items, by reason code.
- **Regression check (catalog B4).** Refuse a merge into a fixed item; treat recurrence as new.
- **Multi-step replay** in the retest card (login, then request), and a no-redirect option for the Python form.
- **Property-based tests**: random URL spellings that must share a claim key, and random merges that must never lose a member or a chain step.

## v2: a local "non-unique range"

A docker-compose lab whose only job is to produce the classes in the catalog on purpose, with an answer key, so any tool's export can be scored against it.

**Components**

| Component | What it produces | Catalog classes |
|---|---|---|
| A small vulnerable API (two roles, numeric and UUID object IDs, one real IDOR, one real time-based injection, one real SSRF, one stored XSS) | The true findings the answer key counts | F3, E4, C10, D4 |
| A WAF in front of it with a challenge page and one payload family blocked, while another encoding reaches the origin | "Blocked at edge, origin unknown" | C4, D4 |
| A shared cache with one unkeyed header | Cached 200s, and one real cache-poisoning case | C6 |
| A load-balanced pool of three back ends, one of them a stale build | "Works one time in N" | C7, A3 |
| An SPA catch-all and a GraphQL endpoint that returns 200 on error | Soft 404s and 200-on-error | D1, D2, D3 |
| Several aliases and a legacy host that redirects, plus one off-origin redirect | One finding, many addresses; a scope question | A1, A2, A5, O2 |
| A callback intermediary (a link-scanner stand-in that fetches URLs it sees) and a switchable egress block | DNS-only, intermediary and blocked callbacks | C3, C10, E6 |
| A tester-side proxy that injects its own headers | Tester-path artifacts | C1 |
| Seeded test identities and a reset script | Lockouts and contamination to clean up | C5, B5, L3 |

**Answer key.** One JSON file listing every true finding with its claim key, chain membership and expected severity, and every planted artifact with the class it belongs to and the state it should end in (merged, demoted with a reason code, blocked at edge, scope hold, rebaseline). Nothing in the answer key should be visible to the tool under test.

**Scorer.** Reads any tool's export through the v1.1 adapters and reports, per class:
- true findings found, missed, and wrongly closed;
- artifacts correctly labelled versus reported as findings;
- merges that were right, merges that hid a distinct root cause, and missed merges;
- closes without an oracle or a positive control.

It reports by class and by rule, never a single headline score, and it ships with the results of running v1's own checker against the range, including where the checker is wrong.

**Ground rules for the range.** Local only, nothing listening beyond localhost, synthetic data, no real product names in the planted components, and a teardown script that leaves nothing behind.
