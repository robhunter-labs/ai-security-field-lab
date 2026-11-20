# AI × Security field lab

This is where I keep the working side of my writing about AI and security: studies, benches, and small harness experiments, each tied to a piece on [robhunterworks.com](https://robhunterworks.com/writing/). I'm a practitioner exploring the edges, not someone handing down final answers. Every entry says what was actually tested and what wasn't.

Start with a study. Each entry links to the essay, the first thing to open, and what the evidence supports. Bigger pieces live in their own repositories and are indexed here; smaller ones get a folder on this shelf.

| Study | Start here | Evidence |
|---|---|---|
| [Proof Outside the Model](https://robhunterworks.com/writing/proof-outside-the-model/) | [Run the validation package](validation-package/README.md#how-to-run-it): a checker that refuses records where a filter closes what only an oracle may close, a catalog of 103 ways a candidate can be duplicate, untrue or not actionable, and 30 synthetic fixtures | Checked on the included synthetic fixtures; operational use unmeasured |
| [Where the Time Goes on a Local Model](https://robhunterworks.com/writing/where-the-time-goes-on-a-local-model/) | [Timing results](https://github.com/robhunter-labs/local-model-bench/blob/main/results/2026-10-21-timing/SUMMARY.md) and a [runner to time your own model](https://github.com/robhunter-labs/local-model-bench/tree/main/bench/timing) | Observed: 32 calls on one machine, Oct 21, 2026 |
| [The Model That Says Yes](https://robhunterworks.com/writing/the-model-that-says-yes/) | [Pilot summary](https://github.com/robhunter-labs/local-model-bench/blob/main/results/pilot-transcribed/SUMMARY.md), then the bench's [spec](https://github.com/robhunter-labs/local-model-bench/blob/main/SPEC.md) and dry run | Pilot observed once on one laptop; bench checked on the included synthetic fixtures |
| [Capital One's VulnHunter](https://robhunterworks.com/writing/vulnhunter-crapi/) | [Inspect the historical run](https://github.com/robhunter-labs/vulnhunter-crapi-field-study#start-here) · [v1.0.0 release](https://github.com/robhunter-labs/vulnhunter-crapi-field-study/releases/tag/v1.0.0) for citation | Observed in one controlled run |
| [When the Machine Finds More](https://robhunterworks.com/writing/when-the-machine-finds-more/) | [Try the synthetic review exercise](https://github.com/robhunter-labs/vulnhunter-crapi-field-study/tree/main/source/review-workbench) | Checked on the included synthetic fixtures |
| [Declared, Not Wired](https://robhunterworks.com/writing/declared-not-wired/) | [Run the four-route example](https://github.com/robhunter-labs/declared-not-wired#run-it) | Checked on the included synthetic fixtures; not run against a live agent framework |

The labels mean the same thing everywhere on this shelf: **Observed** (it happened, and the record is in the repo), **Checked on the included synthetic fixtures** (the code runs and passes its own tests on the fixtures here, but hasn't been run against a real system), and **Planned** (written down so it gets done; not done). The practice framework, a document set, uses Published instead.

## Planned

These shelves are empty on purpose. An empty shelf says what's coming without pretending it's here.

- **A skill server for every model.** One set of skills served to unlike agents, and the security questions that raises.
- **Swarm, fleet, or loop.** Comparing orchestration patterns with real runs, not metaphors.

## Related shelves

- [dunvaric-kingdom](https://github.com/robhunter-labs/dunvaric-kingdom): the public shelf of the Dunvaric Kingdom, the system I use to direct sustained work with AI agents, organized by its nine shared crafts.
- [penetration-testing-practice-framework](https://github.com/robhunter-labs/penetration-testing-practice-framework): the practice framework.

Use what helps and challenge what doesn't. If you've tested the same edge and seen something different, I'd like to hear it: open an issue on the study's repository or write to hello@robhunterworks.com.

Copyright © 2026 Rob Hunter. Original material is released under the MIT license in `LICENSE`.
