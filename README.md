# SQS - Skill Quality Suite

[![quality](https://github.com/letsloose501/sqs-skills/actions/workflows/quality.yml/badge.svg)](https://github.com/letsloose501/sqs-skills/actions/workflows/quality.yml)
[![license: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![python: 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://github.com/letsloose501/sqs-skills/actions/workflows/quality.yml)
[![no dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#install)
[![skills.sh](https://skills.sh/b/letsloose501/sqs-skills)](https://skills.sh/letsloose501/sqs-skills)
[![GitHub Marketplace](https://img.shields.io/badge/marketplace-skill--quality--suite-2ea44f?logo=github&logoColor=white)](https://github.com/marketplace/actions/skill-quality-suite)

**SQS is a linter, validator, security scanner and evaluation harness for AI Agent Skills
(`SKILL.md`) - and it tells you which skill to fix or write next, from the work you
actually do.** It validates a skill against the
[Agent Skills specification](https://agentskills.io/specification), lints the
instructions an agent will follow, scans a skill for secrets, prompt injection and
dangerous scripts before you trust it, checks whether it works on ten other agents, and
measures whether it improves the agent's work at all.

For Claude Code, OpenAI Codex, Cursor, Gemini CLI, Antigravity, OpenCode, Cline, Roo
Code, Windsurf and GitHub Copilot. 101 coded rules, each one watched firing on a test
case. Python standard library only; the static half is offline and deterministic.

```bash
python scripts/sqs.py check    ./my-skill                # lint and validate: the everyday checks
python scripts/sqs.py security ./my-skill                # before you install a stranger's skill
python scripts/sqs.py compat   ./my-skill --harness all  # will it work on another agent
python scripts/sqs.py discover                           # which skill to fix or write next
python scripts/sqs.py improve  ./my-skill                # what to change in this one, and why
python scripts/sqs.py eval     ./my-skill --trigger      # does it actually fire (paid)
python scripts/sqs.py explain  ST008                     # what a finding means, and the fix
```

`scripts/` is inside the installed skill folder; in a clone of this repository it is
`skills/skill-quality-suite/scripts/`.

## What sets it apart

**The evidence comes from your own sessions.** A trigger set an author writes tends to
restate the description. SQS reads your local Claude Code transcripts instead - read-only,
nothing leaves the machine - and reads what the agent *did*: which skill loaded, which
scripts ran, which files changed. From that:

- `discover` lists the skills whose own scripts ran in sessions that never loaded them (the
  description missed), and the documents and scripts you return to in session after session
  with no skill loaded (a skill nobody wrote yet), each with the prompts that led there;
- `improve <skill>` puts the rule findings with their fixes next to the prompts that
  really reached the skill, the ones a neighbour won, what the agent kept looking up after
  it loaded, the calls that failed there again and again, and how often you stopped it;
- `improve <skill> --transcripts DIR` cuts the skill's latest loads out of your history,
  secrets masked, with the skill text that loaded that day, for a model to judge whether
  each step was followed to the end - the skipped check that no error ever reports. The
  writing is free; the judging is paid and asked for first
  ([how](skills/skill-quality-suite/references/judging-sessions.md));
- `cases --from-history` turns those prompts into a trigger set in your own words;
- a **mistakes journal** - one four-line note per mistake the agent catches itself making,
  reviewed into rules and gates - feeds both: `improve` lists the entries that name the
  skill, including those a review already cleared from the folder but git remembers
  ([how to keep one](skills/skill-quality-suite/references/mistakes-journal.md)).

The agent running the skill reads that evidence and proposes; nothing is created or
rewritten without your yes. Every proposed edit first passes a bar - would the rule have
prevented the failure, did the skill not already say it - and most do not; the ones that
do arrive as a drafted file and its diff.

**Nothing paid starts on its own.** The evaluation half runs an agent and costs money, so
the skill offers it, says what a run costs (about $0.21 per capped trigger run, measured),
and says it pays off only when you keep measuring across edits.

**A regression gate that knows its own noise.** `eval --compare` fails a drop in trigger
recall only when it survives the runs' own variance, and can pull the neighbouring skills
into the pass so you see whether an edit stole their requests.

## Use it when

- a skill **does not fire**, fires on a neighbour's work, or half-works and silently skips
  steps;
- you are about to **install a skill somebody else wrote**, and want to know what it can
  do to your machine first;
- you **renamed** a file, a heading or a skill, and something now points at nothing;
- you are about to **publish** a skill: personal paths, licence, version drift, and a
  repository whose test corpus would ship with it;
- you changed a description and want to know whether the skill got **better or worse**;
- you want to know **which skill to write next**, or whether a new one would only
  **collide** with one you have.

| Question | Command |
|---|---|
| Can it load? Is it valid? | `check` (structure, spec) |
| Is it worth loading? | `quality` |
| Is it safe to install? | `security`, `capabilities` |
| Is it portable? | `compat` |
| Which skill wins this wording, offline? | `route --prompt "..."` |
| Does it fire? | `eval --trigger` (paid) |
| Does it actually help? | `eval --runtime` (paid) |
| Did the last change make it worse? | `eval --compare v1 v2` |
| What should be true of it, and is it? | `cases` |
| What do people actually type to reach it? | `cases --from-history` |
| What should I change in it? | `improve` |
| Was it followed to the end once it loaded? | `improve --transcripts DIR`, then a judge (paid) |
| Which skill should I fix or write next? | `discover` |
| Which mistakes keep happening with it? | `improve` with a mistakes journal |
| Would a new skill just collide with an old one? | `new <name> --seed WORD` |
| Can it be published? | `publish` |

📖 **[Documentation](https://letsloose501.github.io/sqs-skills/)** ·
🧪 **[Worked examples with real output](examples/)** ·
📋 **[All 101 rules](docs/quality-rules.md)**

## Why

A skill loads in two stages: `SKILL.md` first, then its references through the links
inside it. When a link breaks, **nothing crashes and nothing complains.** The agent
silently skips the step, and the only symptom is that the work came out worse than
usual, with no explanation. SQS turns each class of silent breakage into a loud one, and
sorts them by *when* they would have bitten:

| Module | What it catches | When it bites |
|---|---|---|
| `structure` | broken links, orphans, section pointers, budgets | today, silently |
| `spec` | layout, unclosed fences, reserved words, asset weight | on publication |
| `quality` | a description that never says *when*, vague bounds, placeholders | every run, a little |
| `compat` | what will not survive a move to another agent | on somebody else's machine |
| `security` | secrets, destructive commands, injection, hidden characters | when you install a stranger's skill |
| `capabilities` | what a bundled script *can* do - network, subprocess, environment, undeclared packages - and the commands the skill runs the moment it loads | when you install a stranger's skill |
| `cases` | a promise with no step behind it, an expectation it never claimed, a capability it never announced | the first time you rely on it |
| `evals` | the eval files, the routing invariants, a case set that only restates the description | when a neighbour's description moves |
| `eval` | does it fire, does it help, did the last edit make it worse | after every change, if you let it |
| `publish` | personal paths, missing licence, version drift, an update that quietly gained reach, a README installing from the wrong owner, tests and docs shipping inside the skill | the moment it leaves your machine |
| `fix` | the repairs with exactly one correct answer | - |

Every rule was run against real skills before it shipped, and several found something the
first time:

- 37 of 105 positive cases in one real routing set repeat their skill's description word
  for word, so they pass by string match (`EV010`);
- a guide to the load-time command syntax in a public marketplace runs its own 14 examples
  on load - a plain code block does not stop them, watched on a live run (`CB004`);
- a README in the same marketplace tells readers to install a plugin from a marketplace
  that does not list it (`PB014`);
- this repository shipped its own attack corpus to every user while `SKILL.md` sat at the
  repository root; two marketplace scanners failed it largely for that, and all three
  passed it once the skill moved into its own folder (`PB015`).

### What published measurements say about skills

- **A skill buys reliability, not a better answer.** In SkillAxe's comparison, among tasks
  where the agent produced output at all, quality was 57.1% with the skill and without it;
  the whole gain came from producing output more often, 46.7% of tasks to 72.7%
  ([arXiv 2606.10546](https://arxiv.org/abs/2606.10546)). A skill that silently skips a step
  loses exactly that - which is why broken links and unreachable steps come first in `check`.
- **Most skills carry weight they do not need.** Across 55,315 public skills, 26.4% lack a
  routing description entirely and over 60% of body content is non-actionable, while
  reference files can inject tens of thousands of tokens per invocation
  ([SkillReducer, arXiv 2603.29919](https://arxiv.org/abs/2603.29919)). That is what the
  description rules and the `SKILL.md` and reference budgets are for.
- **Who writes the skill matters.** On SkillsBench, curated skills raised the average pass
  rate by 16.2 percentage points; skills the model wrote for itself gave no benefit on
  average (-1.3) ([arXiv 2602.12670](https://arxiv.org/abs/2602.12670)).
- **An improvement has to beat the noise, and be checked on data it was not tuned on.**
  SkillOpt accepts an edit to a skill only when it strictly improves a held-out validation
  score ([arXiv 2605.23904](https://arxiv.org/abs/2605.23904)). On three Kotlin repositories,
  a +4.9-point gain from an optimiser could not be separated from the agent's run-to-run
  variance at the size of dataset one repository supplies
  ([Skill Issue, arXiv 2609.12742](https://arxiv.org/abs/2609.12742)). NVIDIA's SkillEvaluator
  ran 85% of its skills at a single attempt per task and reports no confidence intervals
  ([NVIDIA](https://developer.nvidia.com/blog/evaluating-ai-agent-skill-performance-with-nvidia-skillevaluator/)).
  SQS splits every trigger set 60/40 into train and validation, and `--compare` judges a
  drop against the spread of the runs themselves.
- **A stranger's skill is a supply-chain input.** One study found at least one vulnerability
  in 26.1% of 31,132 skills from two marketplaces
  ([arXiv 2601.10338](https://arxiv.org/abs/2601.10338)); an audit of 3,984 skills found a
  critical issue in 534 and 76 confirmed malicious payloads
  ([Snyk, ToxicSkills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/)).
  That is what `security` and `capabilities` are for, and why `eval --runtime` will not run
  such a skill until you say you have read it.

## Install

As a skill, through the cross-agent installer - for Claude Code, Cursor, Codex, Windsurf,
Gemini and the rest of the agents `skills` supports:

```bash
npx skills@1 add letsloose501/sqs-skills
```

The installer copies `skills/skill-quality-suite/` - `SKILL.md`, `references/`, `scripts/` -
and nothing else. The test corpus, the docs and CI stay in the repository.

By hand, if you would rather see what lands:

```bash
git clone https://github.com/letsloose501/sqs-skills
cp -r sqs-skills/skills/skill-quality-suite ~/.claude/skills/
```

Or as a plain tool: clone anywhere and call `skills/skill-quality-suite/scripts/sqs.py`.
It finds the skills folder on its own, or takes `--skills-dir`.

## In CI

```yaml
- uses: letsloose501/sqs-skills@v2
  with:
    path: .
    strict: "true"
    harness: all
    upload-sarif: "true"        # needs security-events: write on the job
```

The action is on the [GitHub Marketplace](https://github.com/marketplace/actions/skill-quality-suite).
It annotates the diff, writes SARIF for code scanning, and fails the job on the findings
that count. `changed: "true"` checks only the skills the diff touched; `baseline: "true"`
reports only what the baseline file does not already carry, which is how the gate goes on
over a tree with three hundred existing findings without turning the build red on day one.

Before the commit, rather than after:

```yaml
repos:
  - repo: https://github.com/letsloose501/sqs-skills
    rev: v2
    hooks:
      - id: skill-quality-suite            # the skills this commit touches
      - id: skill-quality-suite-security   # for a skill that arrived from elsewhere
```

## Multi-harness compatibility

The one thing about a skill you cannot check on your own machine.

```
python scripts/sqs.py compat ./my-skill --harness all
```

Each feature of the skill - a frontmatter field, a directory, a tool name, a hard-coded
path into someone's skill folder - is classified per harness as `PORTABLE`, `ADAPTABLE`,
`HARNESS_SPECIFIC`, `INVALID` or `UNKNOWN`. **`UNKNOWN` is not `NOT_SUPPORTED`.** Every row
rests on that project's own documentation, dated when it was last read, and where the
documentation is silent the answer is `UNKNOWN` rather than an invented incompatibility.
Adding a harness is one file in `scripts/harnesses/`. Porting a skill to another harness
is [porting.md](skills/skill-quality-suite/references/porting.md): read the target's own
page, plan, write a copy.

## Reading the output

```
⛔ SP004  `name: video-tools` does not match the folder `video` (SKILL.md)
⚠️  ST006  SKILL.md is 21370 B > the 15000 B budget (SKILL.md)
·   QL006  as needed - lines 191, 295 (SKILL.md:191)
```

- **⛔ error** - fix it. Nothing here is cosmetic.
- **⚠️ warning** - a decision, not a defect. An orphan file is either unwired or no longer
  needed, and only you know which.
- **· info** - a nudge. Real, small, safe to leave.

Every finding carries a rule code: `sqs.py explain ST008` prints the reasoning and the fix,
`sqs.py rules` lists all 101. `--format text|json|github|sarif|board`, `--strict`,
`--changed`, `--since`, `--baseline`, `--min-confidence`, `--score`. Exit codes: `0` clean,
`1` findings that count as failures, `2` usage error.

**SQS does not run the tree it is reading.** The structure engine is the one the skill
ships; a target's own `evals/run_evals.py` is reported as not executed (`EV006`) unless you
pass `--trust-target` for a tree you own. See [SECURITY.md](SECURITY.md).

## Silencing a finding

- **a line** - `sqs-allow: SE002` on it or just above it, for one quotation of a pattern;
- **a file** - `sqs-allow-file: SE001, SE002` in its first 25 lines, for a file whose whole
  job is to hold the patterns;
- **the tree** - `sqs.config.json` beside the skills (`rules`, `ignore`, `allow_dirs`,
  `harnesses`, `lang`);
- **material that is not payload** - `.sqsignore` at the skill root, one glob per line. It
  hides the path from SQS only; an installer and other scanners still see it (`PB015`).

Write down *why* next to the entry. A silenced rule with no reason gets un-silenced by the
next person who reads the file, including you.

## Design notes

**Precision over coverage.** A rule earns its place by being checkable: it names a file and
a line, or it does not ship. Heuristics that cannot point at anything live in
[writing-rubric.md](skills/skill-quality-suite/references/writing-rubric.md), where a human
applies judgement. A linter that cries wolf stops being read.

**One registry.** `scripts/rules.py` is the single place a rule code is defined; `sqs.py
rules --audit` fails when an engine and the registry disagree.

**Every rule has been watched firing.** `tests/fixtures/` holds small skill trees with an
`expect.json` beside each: the codes a run must report and the codes it must not. The two
cases that matter most, `clean/` and `escape-hatches/`, must report **nothing at all**.

**The evaluation layer is tested without a model.** `--provider fake` replays canned runs,
so the confusion matrix, the baseline/treatment split and the regression gate have tests
that cost nothing.

## Documentation

- [Skill validation](docs/skill-validation.md) · [Skill security](docs/skill-security.md) ·
  [Quality rules](docs/quality-rules.md) · [Compatibility](docs/compatibility.md) ·
  [Case sets](docs/case-sets.md) · [Evaluation](docs/evaluation.md) ·
  [Publishing](docs/publishing.md)
- Walkthroughs: [How to validate an AI Agent Skill](docs/how-to-validate-an-agent-skill.md) ·
  [How to secure Agent Skills](docs/how-to-secure-agent-skills.md)
- For whoever is editing a skill: the [references](skills/skill-quality-suite/references/) -
  the writing rubric (its vocabulary is Matt Pocock's, from
  [`writing-for-agents`](https://github.com/mattpocock/skills/tree/main/skills/productivity/writing-for-agents)),
  creating a skill, from history to a proposal, evaluating, publishing, porting.

## Support, contributing, licence

- Questions, bugs, false positives: [SUPPORT.md](SUPPORT.md). Security: [SECURITY.md](SECURITY.md).
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). People: [CONTRIBUTORS.md](CONTRIBUTORS.md).
- Licensed under [Apache-2.0](LICENSE). Redistributions and derivative works keep the
  [NOTICE](NOTICE) file, which names SQS and its author. Releases up to v1 were published
  under MIT and stay under it.
