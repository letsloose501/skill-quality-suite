# Judging sessions

Whether a skill was followed to the end once it loaded: the step skipped in silence, the
check left out before "done", the thing the agent had to work out by trial because the
skill never said it. No count in `improve` sees these: nothing errors when a step is
skipped. A model has to read the load beside the skill, so this is **paid**: offer it,
say it spends the usage window in proportion to the characters `improve` printed, and
start only on a yes.

The two questions and the bar for turning a verdict into an edit are adapted from Warp's
skill-doctor (MIT; its procedure-compliance and efficiency scorers and its
skill-improvements guide). What changed: skill-doctor grades whole conversations for a
report card; this judges one skill's loads, against the text that loaded, for an edit.

## 1. Write the loads

```
sqs.py improve <skill> --transcripts <dir> [--max-loads 12]
```

Free, local, nothing sent. Under `<dir>/<skill>/`: one file per load (the request, what
the agent handed the skill, every call and its result, the person's next message),
`loaded-vN.md` for each distinct skill text that loaded, and `index.json`. Put `<dir>`
in the scratchpad, never in the user's repository. Loads from sessions that edited the
skill are left out: that is the author experimenting, not the skill failing.

## 2. Judge each load

Read the `loaded-vN.md` the load names first - the skill as the agent saw it that day -
then the load. Record two verdicts per load, each with one to three sentences quoting
the moment that decided it.

**Adherence** - did the agent do what the loaded skill required, for this request?

| Verdict | Score | When |
|---|---|---|
| `followed` | 1 | every step that applied was done, with its checks, constraints and output form |
| `slipped` | 0.8 | a low-stakes step slipped; nothing the person had to catch |
| `skipped` | 0.2 | a required step, check or constraint left out - above all a verification skipped while reporting done, or a protective rule broken; one such is enough |
| `no_evidence` | - | the load ends before the skill's work shows (the session ended, another skill took over) |

Judge only the steps this request reached: a publishing step does not apply to a load
that never published. A step that failed and was then abandoned in silence is
`skipped`; one that failed, was diagnosed and fixed is not.

**Coverage** - did the skill say what the agent needed?

| Verdict | When |
|---|---|
| `covered` | the agent went straight through on what the skill said |
| `worked_out` | the agent found by trial, lookup or the person's correction something the skill could have stated - name it: a path, a flag, a precondition, an order of steps |
| `no_evidence` | as above |

A `worked_out` needs the thing to be stable: the same answer would hold next time. A
fact about this one task (this file's contents, this user's choice) is the task, not a
gap in the skill.

Bad reason: "The agent mostly followed the skill but could have been more careful."
Good reason: "Step 3 says to run `check_done.py` before reporting; the load reports
«готово» after the Edit, and the person's next message is «а проверку?»." The first
names no step and no moment, so nobody can dispute it; the second can be checked
against the load file in a minute.

## 3. From verdicts to edits

Only failed loads are evidence: `skipped`, or `worked_out`. A `followed`/`covered` load
proves nothing needs changing and suggests nothing. Group the failed loads by cause,
not by verdict, and order the groups by how often times how bad.

Then hold every group to the bar in
[from-history.md](from-history.md#before-an-edit-to-a-skill-that-exists). Most do not
pass it, and a run that ends with no edit, each group with the reason it failed the bar,
has done its job.

A group that passes becomes a draft, never an edit:

1. Say the rule and the part of the skill that owns it, in one sentence.
2. Write the full proposed file to `<dir>/proposed/<skill>/SKILL.md`, changing only
   what the group justifies; prefer replacing a passage over adding one.
3. Show `git diff --no-index <skill>/SKILL.md <dir>/proposed/<skill>/SKILL.md`, the load
   files it rests on, and wait for a yes. The real file is not touched before it.
4. After a yes: `sqs.py check <skill>`, and a backtest - replay one old failed load by
   hand against the new text and say whether it would have gone differently.

## What this cannot see

- Loads before transcripts were kept, and work in another harness: only Claude Code's
  own history is read.
- Whether a `followed` load produced good work: that is `eval --runtime`, with the skill
  and without it.
- Intent the person never typed. A load with no next message is not approval.
