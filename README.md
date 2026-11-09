# AI × Security field lab

This is where I keep the working side of my writing about AI and security: studies, benches, and small harness experiments, each tied to a piece on [robhunterworks.com](https://robhunterworks.com/writing/). I'm a practitioner exploring the edges, not someone handing down final answers. Every entry says what was actually tested and what wasn't.

Bigger pieces live in their own repositories and are indexed here. Smaller ones get a folder on this shelf as they're written.

Status labels are the same for every study listed here (the practice framework, a document set, uses Published instead): **Observed** (it happened, and the record is in the repo), **Built, not exercised** (the code exists and passes its own tests, but hasn't been run against a real system), and **Planned** (written down so it gets done; not done).

| Study | What it is | Status | Essay | Where |
|---|---|---|---|---|
| Declared, not wired | Paired allowed and denied routes that show whether a declared control actually sits on the path that acts | Built, not exercised | [Declared, Not Wired](https://robhunterworks.com/writing/declared-not-wired/) | [declared-not-wired](https://github.com/robhunter-labs/declared-not-wired) |
| VulnHunter against crAPI | One controlled evaluation of an AI security tool against a deliberately vulnerable API | Observed (one controlled run) | [VulnHunter field study](https://robhunterworks.com/writing/vulnhunter-crapi/) | [vulnhunter-crapi-field-study](https://github.com/robhunter-labs/vulnhunter-crapi-field-study) |
| Local model bench | A bench, threat model, controls, and pen-test map for a refusal-reduced model running on one laptop | Observed, plus built-not-exercised checks | [The Model That Says Yes](https://robhunterworks.com/writing/the-model-that-says-yes/) | [local-model-bench](https://github.com/robhunter-labs/local-model-bench) |
| When the machine finds more | A synthetic review exercise for deciding what a person does with a tool's candidate findings | Built, not exercised | [When the Machine Finds More](https://robhunterworks.com/writing/when-the-machine-finds-more/) | [vulnhunter-crapi-field-study](https://github.com/robhunter-labs/vulnhunter-crapi-field-study/tree/main/source/review-workbench) |
| Validation package | A schema for the minimum validation package, a checker that refuses records where a filter closes what only an oracle may close, a catalog of 103 ways a tool's candidate can be duplicate, untrue, or not actionable, and 30 synthetic fixtures | Built, not exercised | [Proof Outside the Model](https://robhunterworks.com/writing/proof-outside-the-model/) | [validation-package](validation-package/) |

## Planned

These shelves are empty on purpose. An empty shelf says what's coming without pretending it's here.

- **A skill server for every model.** One set of skills served to unlike agents, and the security questions that raises.
- **Swarm, fleet, or loop.** Comparing orchestration patterns with real runs, not metaphors.

## Related shelves

- [dunvaric-kingdom](https://github.com/robhunter-labs/dunvaric-kingdom): the public shelf of the Dunvaric Kingdom, the system I use to direct sustained work with AI agents, organized by its nine shared crafts.
- [penetration-testing-practice-framework](https://github.com/robhunter-labs/penetration-testing-practice-framework): the practice framework.

Use what helps and challenge what doesn't. If you've tested the same edge and seen something different, I'd like to hear it: open an issue on the study's repository or write to hello@robhunterworks.com.

Copyright © 2026 Rob Hunter. Original material is released under the MIT license in `LICENSE`.
