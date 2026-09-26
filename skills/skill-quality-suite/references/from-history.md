# From your history to a proposal

Which skill to write next, and which existing one keeps missing, read off what the agent
actually did in the user's Claude Code sessions. Open this before running `sqs.py
discover`, or when `improve` reports scripts that ran while the skill never loaded.

`discover` and `improve` read the agent's actions out of the user's Claude Code
transcripts - the scripts it ran, the files it changed, the skills it loaded - because
the wording of a request alone was measured as noise. They print evidence and decide
nothing. The deciding is yours, in this conversation, and it costs nothing extra:

1. Run `sqs.py discover`. Section 1 names the skills whose own scripts ran in sessions
   that never loaded them; section 2, the documents and scripts the user returned to in
   several sessions with no skill loaded.
2. Read the prompts under each row. Group the rows that are one task; drop a row whose
   prompts are conversation, or a project being built rather than a task being repeated.
3. Give each group one of four verdicts, and say what it rests on:
   - **Write** - a task no skill covers, repeated, specific enough to have a trigger;
   - **Improve, then write** - worth a skill, but the rows do not yet show one task; name
     what the next occurrence has to show;
   - **Absorb into `<skill>`** - an existing skill already takes most of these requests
     (`sqs.py new <name> --seed <word>` shows where they go today): a branch there, not a
     neighbour that would collide with it;
   - **Drop** - conversation, a one-off, or a project being built rather than a task
     being repeated.

   For a skill in section 1 the verdict is about its description: `sqs.py improve <skill>`,
   then the change that would have caught those prompts. Check first that no `CLAUDE.md` or
   hook sends the agent to the script directly; then the routing works, just not through
   the skill, and the verdict is Drop.
4. Say where a new skill lives, from the project column. Work seen in one project belongs
   in that project's `.claude/skills/`; work seen in two or more is general and goes to the
   user's own skills folder. A lesson keeps the scope it was learned in until it shows up
   somewhere else.
5. Propose, one line per group, and wait for a yes before writing anything. On a yes,
   build it through [creating-a-skill.md](references/creating-a-skill.md): from one real run
   of the work, not from the rows.

Bad: "Created skill `budget` from your history." Good: "`plans/budget.md` was edited in nine
sessions with no skill loaded, each time to move a deadline or a limit. A branch in your
planning skill, or a skill of its own? Say which, and I will write it from the next such
edit." The first acted on a list; the second names the evidence, the choice and who makes it.

## Before an edit to a skill that exists

Every source of a proposed change - a failed call in `improve`, a lookup repeated across
sessions, a mistakes-journal entry, a load judged in
[judging-sessions.md](judging-sessions.md) - passes this bar first. Adapted from Warp's
skill-doctor guide (MIT). Propose an edit only when all four hold:

- the failure comes from a missing, wrong or underspecified instruction **in this skill**,
  not in a `CLAUDE.md`, a hook, the harness, or the code the skill calls;
- you can name the one reusable rule the skill should have stated, and the part of it
  that owns that rule;
- had the rule been there and followed, this failure would not have happened;
- it shows in two or more sessions, or once but proves a missing contract: a protective
  rule, lost work.

And propose nothing when:

- **the skill already required it and the agent ignored it.** A louder sentence will be
  ignored the same way. Once is noise; repeated, the step moves out of prose into a
  script the skill runs or a gate - the ladder in
  [mistakes-journal.md](mistakes-journal.md);
- the same request with the same tools went differently once: model variance;
- the only edit available restates the instruction, hedges it, or adds an example from
  these very sessions - a patch for today's case, not a rule;
- the real fix is outside the skill: a bug in its script, the harness, another file.

When nothing passes, say so group by group, with the reason each one failed the bar. An
empty proposal backed like that is a result; a speculative edit is worse than none,
because it grows the skill for every future load. Prefer replacing a passage to adding
one, and draft before editing: the proposed file and its diff, as in
[judging-sessions.md](judging-sessions.md#3-from-verdicts-to-edits), and the real file
only after a yes.

## What the two readings count, and what they cannot see

- **Scripts run while the skill never loaded** (`discover` section 1, `improve` section 2):
  a script inside `.claude/skills/<skill>/` run from the shell, in a session that had not
  loaded that skill up to that turn and never edited it. A session that edits a skill is
  building it, and running its scripts there is testing them. A typed `/command` counts as
  a load.
- **Work repeated with no skill** (`discover` section 2): a script run, or a document
  changed, in two or more sessions none of which had loaded any skill up to that turn.
  Left out on evidence from a real history: a script that was itself edited anywhere (the
  project under development, not a tool in use), source-code files, the harness's own
  files (`MEMORY.md`, `CLAUDE.md`, anything under `.claude/`), scratch and temp files,
  and a script name that only appears inside text - a heredoc, a commit message.
- **Failed calls and stops** (`improve` section 3): a call that failed inside the skill's
  work in two or more sessions, with its last error - the skill keeps leading the agent
  into the same wall, so fix the step that leads there. And how many loads the person
  stopped, beside the share of turns stopped with no skill loaded: counts, not a verdict.
- **Secrets are masked.** Every printed prompt goes through the same token shapes the
  `security` module detects, plus a word for a secret followed by a colon and a value; a
  person pastes credentials into a chat, and a report of their prompts would print them.
- **Not visible**: intent. Two rows can be one task, one row can be two, and a document
  edited often may be the output of a skill that simply was not asked for. The prompts are
  printed so that judgement is made by whoever reads them, which is the step above.
- Everything is read locally from the `projects` folder of Claude Code's home directory,
  where it keeps a transcript per session (`--history-dir` for another
  place); nothing leaves the machine, and nothing is written.
