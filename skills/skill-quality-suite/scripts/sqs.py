#!/usr/bin/env python3
"""skill-quality-suite - one command for every check a skill can be put through.

    sqs.py check                     structure + spec + quality + compat + security
    sqs.py check my-skill --strict   one skill, warnings count as failures
    sqs.py structure|spec|quality|compat|security|capabilities|publish|evals|fix  one module
    sqs.py explain ST008             what a code means and how to fix it
    sqs.py rules --module quality    the registry
    sqs.py new my-skill              scaffold a skill that already passes
    sqs.py route --prompt "..."      which skill this wording resembles, offline

The modules are separate because they fail at different moments. Structure breaks
today, silently. Spec breaks on publication. Compat breaks on somebody else's machine.
Evals break when a neighbouring description moves. Running them as one pass would
report all four with the same urgency, which is how a report stops being read.

Output: `--format text` (default), `json`, or `github` for CI annotations.
Exit codes: 0 clean · 1 findings that count as failures · 2 usage error.

A line carrying `sqs-allow: SE002` (or `sqs-allow: *`) is exempt from that code - the
escape hatch for a file that documents a pattern rather than using it.
"""
import argparse
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import baseline as baseline_store                               # noqa: E402
import capabilities                                             # noqa: E402
import cases as caseset                                         # noqa: E402
import compat                                                   # noqa: E402
import evalcheck                                                # noqa: E402
import fix as fixer                                             # noqa: E402
import portability                                              # noqa: E402
import publish                                                  # noqa: E402
import quality                                                  # noqa: E402
import report                                                   # noqa: E402
import security                                                 # noqa: E402
import spec                                                     # noqa: E402
from core import Finding, Skill, discover                       # noqa: E402
from harnesses import registry as harness_registry              # noqa: E402
from model import SkillModel                                    # noqa: E402
from report import RANK, SIGIL                                  # noqa: E402
from rules import (MODULES, RULES, at_least, module_of,        # noqa: E402
                   severity_of, ungraded)

_CODES = r"([A-Z]{2}\d{3}(?:\s*,\s*[A-Z]{2}\d{3})*|\*)"
SUPPRESS_RE = re.compile(r"sqs-allow:\s*" + _CODES)
SUPPRESS_FILE_RE = re.compile(r"sqs-allow-file:\s*" + _CODES)
CHECK_MODULES = ("structure", "spec", "quality", "compat", "security", "capabilities",
                 "cases")


def skills_dir(arg=None):
    """Where the skills live: the flag, then the environment, then the default."""
    if arg:
        return os.path.abspath(os.path.expanduser(arg))
    env = os.environ.get("CLAUDE_SKILLS_DIR")
    if env:
        return os.path.abspath(os.path.expanduser(env))
    up = os.path.dirname(os.path.dirname(HERE))
    if os.path.isdir(up) and any(
            os.path.isfile(os.path.join(up, d, "SKILL.md")) for d in os.listdir(up)
            if os.path.isdir(os.path.join(up, d))):
        return up
    return os.path.expanduser("~/.claude/skills")


def resolve_targets(args, root):
    """(skills, notes) for whatever the user pointed at.

    A target is a path or a name, because both are how people arrive here: a path when
    they are working on one skill or a checkout, a name when they are sweeping their own
    tree. A path that turns out to be a plugin is unwrapped to the skills inside it -
    the plugin's commands, agents and hooks are somebody else's tool's business.
    """
    import glob
    if not args:
        return discover(root), []
    skills, notes = [], []
    for arg in args:
        path = os.path.abspath(os.path.expanduser(arg))
        if not os.path.isdir(path):
            named = os.path.join(root, arg)
            if os.path.isfile(os.path.join(named, "SKILL.md")):
                skills.append(Skill(named))
            else:
                notes.append(f"no skill named `{arg}` and no directory at that path")
            continue
        if os.path.isfile(os.path.join(path, "SKILL.md")):
            skills.append(Skill(path))
            continue
        inside = sorted(glob.glob(os.path.join(path, "skills", "*", "SKILL.md")))
        if inside:
            found = [Skill(os.path.dirname(p)) for p in inside]
            skills += found
            notes.append(f"plugin container `{os.path.basename(path)}`: "
                         f"{len(found)} skill(s) checked, other plugin components "
                         f"(commands, agents, hooks, manifest) were not analysed")
            continue
        loose = sorted(glob.glob(os.path.join(path, "*", "SKILL.md")))
        if loose:
            skills += [Skill(os.path.dirname(p)) for p in loose]
        else:
            notes.append(f"no SKILL.md under `{arg}`")
    return skills, notes


def stored_eval_rows(root, skills):
    """Board rows for the layers that run an agent, from the newest stored run.

    They are stamped with the label and the date they were measured, because a stored
    number is about the version that was measured, not about the files on disk now. A
    board that printed yesterday's 94% next to today's edits would be the most
    convincing wrong answer the suite could give.
    """
    try:
        from evaluation import regression
    except ImportError:
        return []
    if len(skills) != 1:
        return []
    name = skills[0].name or skills[0].folder
    labels = regression.labels(root, name)
    if not labels:
        return []
    payload, best_key = None, None
    for label in labels:
        data = regression.load(root, name, label)
        if not data:
            continue
        # the label breaks a tie: two runs saved in the same second are ordered by the
        # name they were given, which is the order they were written in
        key = (data.get("saved", ""), label)
        if best_key is None or key > best_key:
            payload, best_key = data, key
    if not payload:
        return []
    stamp = f"{payload.get('label')} · {(payload.get('saved') or '')[:10]}"
    rows = []
    trigger = payload.get("trigger")
    if trigger:
        best = None
        for block in trigger.get("sets", {}).values():
            m = block.get("metrics") or {}
            if m.get("precision") is not None:
                best = m
        if best:
            rows.append(("TRIGGER", f"{(best.get('precision') or 0):.0%}/"
                                    f"{(best.get('recall') or 0):.0%}",
                         f"precision/recall, measured {stamp}"))
    runtime_block = payload.get("runtime")
    if runtime_block:
        rate = (runtime_block.get("sides", {}).get("treatment") or {}).get("success_rate")
        rows.append(("RUNTIME", "n/a" if rate is None else f"{rate:.0%}",
                     f"graded task success, measured {stamp}"))
    if len(labels) > 1:
        rows.append(("REGRESSION", "READY",
                     f"`sqs.py eval --compare {labels[-2]} {labels[-1]}`"))
    return rows


def changed_skills(skills, since="HEAD"):
    """(kept skills, note) - only those a git diff touched.

    For a repository with hundreds of skills, where checking all of them on every
    commit costs minutes nobody has. When git cannot answer - not a checkout, no
    commits yet - this returns everything and says so: quietly checking nothing would
    be a green build that looked at no files, which is the worst output a gate has.
    """
    tops = set()
    for cmd in (["git", "diff", "--name-only", since],
                ["git", "diff", "--name-only", "--cached", since],
                ["git", "ls-files", "--others", "--exclude-standard"]):
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace")
        if r.returncode != 0:
            return skills, (f"`{' '.join(cmd)}` failed ({(r.stderr or '').strip()[:80]}) - "
                            f"--changed checked everything instead")
        tops |= {os.path.abspath(line.strip()) for line in r.stdout.splitlines() if line.strip()}
    kept = [s for s in skills
            if any(p == s.root or p.startswith(s.root + os.sep) for p in tops)]
    return kept, f"--changed: {len(kept)} of {len(skills)} skill(s) touched since {since}"


def load_config(root, path=None):
    """`sqs.config.json` beside the skills, unless a path is given.

    Keys: `rules` (code -> off/info/warning/error), `ignore` (skill names),
    `agents` (runtimes the skills target), `lang`, `allow_dirs`, `mistakes` (the
    mistakes journal folder `improve` and `discover` read).
    """
    path = path or os.path.join(root, "sqs.config.json")
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        print(f"config {path}: {e}", file=sys.stderr)
        return {}


def journal_dir(cfg, flag=None):
    import journal  # noqa: PLC0415
    return journal.resolve(cfg, flag)


def own_tree(root):
    """Is `root` the tree this suite itself is installed in?

    The one tree whose scripts are not material under analysis. Everywhere else `root`
    is a directory somebody handed the suite to be read, and the whole point of reading
    it is that nobody has vouched for what is inside.
    """
    try:
        return (os.path.realpath(root)
                == os.path.realpath(os.path.dirname(os.path.dirname(HERE))))
    except OSError:
        return False


def load_structure_engine(root):
    """check_skills.py, imported rather than shelled out to.

    It is the structure engine and it already carries the rule codes; parsing its
    printed output back into findings would be a second, drifting source of truth.
    """
    # The engine the suite runs is the one it ships in `scripts/`, imported like any
    # other module of the suite. A tree under analysis used to be able to supply its own
    # `check_skills.py`, first unconditionally and later behind `--trust-target`: either
    # way an analyser importing a file out of the material it was pointed at. No path
    # outside this folder is loaded any more, trusted or not.
    os.environ.setdefault("CLAUDE_SKILLS_DIR", root)
    try:
        import check_skills                                     # noqa: PLC0415
    except ImportError:
        return None
    return check_skills


_warned_no_engine = False


def structure_findings(skill, engine):
    if engine is None:
        # A missing tool is not a finding about the skill: giving it a rule code would
        # put "your linter is not installed" in the same list as "your links are
        # broken", and the reader would have to tell them apart.
        global _warned_no_engine
        if not _warned_no_engine:
            _warned_no_engine = True
            print("check_skills.py is missing from this suite's scripts/ - the structure module is "
                  "skipped", file=sys.stderr)
        return []
    # The engine resolves a skill by name under its own SKILLS_DIR, so it is pointed at
    # this skill's actual parent before every call. Without that, `--skills-dir` pointing
    # somewhere else - a checkout, a single skill - makes it look for the folder in the
    # wrong tree and report the skill as missing its own SKILL.md.
    engine.SKILLS_DIR = os.path.dirname(skill.root)
    errors, warnings, _, _ = engine.check(skill.folder)
    return ([Finding(f.code, f.msg, severity="error") for f in errors] +
            [Finding(f.code, f.msg, severity="warning") for f in warnings])


def evals_findings(root, live=False, names=(), trust_target=False):
    """Routing checks, delegated to the runner that owns them."""
    runner = os.path.join(root, "evals", "run_evals.py")
    if not os.path.isfile(runner):
        return [Finding("EV002", "no evals/ beside the skills - nothing verifies that any "
                                 "description still fires on the wording a human uses",
                        severity="info")]
    # The runner belongs to the tree, so running it means running a script out of the
    # directory under analysis. That is the suite's own tree by default and nobody
    # else's: a routing report is not worth executing a stranger's Python for.
    if not trust_target and not own_tree(root):
        return [Finding("EV006", f"{os.path.relpath(runner, root)} belongs to the tree "
                                 "being checked and was not executed; pass --trust-target "
                                 "if the tree is yours",
                        severity="info")]
    cmd = [sys.executable, runner, "--quiet"]
    if live:
        cmd.append("--live")
    for n in names:
        cmd += ["--skill", n]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode == 0:
        return []
    detail = (r.stderr or r.stdout or "").strip() or f"exit {r.returncode}"
    code = "EV003" if live and r.returncode == 1 else "EV001"
    return [Finding(code, detail.replace("\n", "\n        "), severity="error")]


_LINE_CACHE = {}


def _lines(path):
    if path not in _LINE_CACHE:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                _LINE_CACHE[path] = fh.read().split("\n")
        except OSError:
            _LINE_CACHE[path] = []
    return _LINE_CACHE[path]


def _waives(text, code):
    m = SUPPRESS_RE.search(text) or SUPPRESS_FILE_RE.search(text)
    return bool(m) and (m.group(1) == "*" or code in m.group(1))


def suppressed(skill, f):
    """Whether the file or the line waives that code.

    Two scopes, because two different things need waiving. A line-scoped `sqs-allow`
    covers one quotation of a pattern. A file-scoped `sqs-allow-file` in the header
    covers a file whose whole job is to hold the patterns - a rule registry trips every
    rule it describes, and annotating each occurrence would be noise pretending to be
    care.
    """
    if not f.where:
        return False
    lines = _lines(os.path.join(skill.root, f.where))
    if any(SUPPRESS_FILE_RE.search(ln) and _waives(ln, f.code) for ln in lines[:25]):
        return True
    if not f.line:
        return False
    for n in (f.line - 1, f.line - 2):          # the line itself, or the one above it
        if 0 <= n < len(lines) and SUPPRESS_RE.search(lines[n]) and _waives(lines[n], f.code):
            return True
    return False


def collect(skill, modules, cfg, skill_registry, engine, world=None):
    out = []
    for name in modules:
        if name == "structure":
            out += structure_findings(skill, engine)
        elif name == "spec":
            out += spec.check(skill, cfg)
        elif name == "quality":
            out += quality.check(skill, cfg, skill_registry)
        elif name == "compat":
            out += compat.check(skill, cfg, world)
        elif name == "security":
            out += security.check(skill, cfg)
        elif name == "capabilities":
            out += capabilities.check(skill, cfg)
        elif name == "cases":
            out += caseset.check(skill, cfg, cfg.get("descriptions"))
        elif name == "publish":
            out += publish.check(skill, cfg)
        elif name == "evals":
            out += evalcheck.check(skill, cfg)
        elif name == "fix":
            out += fixer.check(skill, cfg)
    for f in out:
        f.skill = skill.folder
        f.root = skill.root
        if f.severity is None:
            f.severity = severity_of(f.code)
    # the config has the last word on severity, including switching a rule off
    overrides = cfg.get("rules", {})
    out = [f for f in out if overrides.get(f.code) != "off" and not suppressed(skill, f)]
    for f in out:
        if f.code in overrides:
            f.severity = overrides[f.code]
    return sorted(out, key=lambda f: (RANK.get(f.severity, 3), f.code, f.where or ""))


def cmd_explain(code, fmt="text"):
    code = code.upper()
    row = RULES.get(code)
    if not row:
        near = sorted(c for c in RULES if c.startswith(code[:2]))
        print(f"no rule {code}." + (f" {code[:2]}xx holds: {', '.join(near)}" if near else ""))
        return 2
    if fmt == "json":
        print(json.dumps(dict(row.as_dict(), why=row.why, how=row.how),
                         ensure_ascii=False, indent=2))
        return 0
    print(f"{code}  {row.title}")
    print(f"module   {module_of(code)}")
    print(f"severity {row.severity}" + ("  ·  `sqs.py fix` can repair it" if row.fixable else ""))
    # The two gradings are about the check, not about the skill: how far to trust the
    # machine on this one, and how often the thing it found is nonetheless intended.
    print(f"detection confidence {row.confidence} · false positives {row.false_positive_risk}")
    print(f"\nwhy      {row.why}")
    print(f"fix      {row.how}")
    return 0


def fixture_coverage():
    """{code: {"positive": n, "negative": n}} from the golden corpus, if it is here.

    The corpus is what turns a rule's metadata from an opinion into a measurement: a
    rule with no positive fixture has never been observed firing, and one with no
    negative fixture has never been observed staying quiet.
    """
    # The corpus lives in the repository, beside `skills/`, not inside the skill: the
    # installer copies the skill's folder, and a corpus of deliberately broken skills has
    # no business in a stranger's skills directory. An installed copy has no corpus.
    suite = os.path.dirname(HERE)
    tests_dir = os.path.join(os.path.dirname(os.path.dirname(suite)), "tests")
    root = os.path.join(tests_dir, "fixtures")
    cover = {}
    if not os.path.isdir(root):
        return None
    # Rules no fixture can reach, declared once and read by both the corpus runner and
    # this audit. Two lists would drift, and the drift would read as coverage.
    try:
        with open(os.path.join(tests_dir, "coverage.json"), encoding="utf-8") as f:
            declared = json.load(f)
    except (OSError, ValueError):
        declared = {}
    for code in declared.get("unit_covered", {}):
        cover.setdefault(code, {"positive": 0, "negative": 0})["positive"] += 1
    # a rule with no engine is not covered and not missing: it is out of the count
    cover["__no_engine__"] = sorted(declared.get("no_engine", {}))
    for dirpath, _, files in os.walk(root):
        if "expect.json" not in files:
            continue
        try:
            with open(os.path.join(dirpath, "expect.json"), encoding="utf-8") as f:
                spec_ = json.load(f)
        except (OSError, ValueError):
            continue
        for code in spec_.get("expect", []):
            cover.setdefault(code, {"positive": 0, "negative": 0})["positive"] += 1
        for code in spec_.get("reject", []):
            cover.setdefault(code, {"positive": 0, "negative": 0})["negative"] += 1
    return cover


def cmd_rules(module=None, audit=False, fmt="text"):
    if audit:
        # Every code an engine can emit has to have a row here. This is the check that
        # keeps the registry from drifting away from the engines that use it.
        # A code-shaped literal anywhere in an engine counts as emitted. Matching only the
        # constructor call would miss every engine that builds the code first and
        # constructs the finding after - which is most of them.
        literal = re.compile(r'"([A-Z]{2}\d{3})"')
        engines = []
        for base in (HERE, os.path.join(HERE, "evaluation")):
            if os.path.isdir(base):
                engines += [os.path.join(base, p) for p in sorted(os.listdir(base))
                            if p.endswith(".py") and p != "rules.py"]
        emitted = set()
        for path in engines:
            if not os.path.isfile(path):
                continue
            with open(path, encoding="utf-8") as f:
                emitted |= set(literal.findall(f.read()))
        orphan = sorted(emitted - set(RULES))
        # ST016 is the opt-in external-link check, which has no engine yet: it is the
        # one row here that documents a gap rather than a rule in force.
        unused = sorted(set(RULES) - emitted - {"ST016"})
        ungraded_codes = ungraded()
        cover = fixture_coverage()
        no_engine = set((cover or {}).pop("__no_engine__", ()))
        untested = sorted(c for c in RULES
                          if c not in no_engine
                          and not (cover or {}).get(c, {}).get("positive")
                          ) if cover is not None else []
        if orphan:
            print("emitted with no row in rules.py: " + ", ".join(orphan))
        if unused:
            print("rows nothing emits: " + ", ".join(unused))
        if ungraded_codes:
            print("no confidence/false-positive grading: " + ", ".join(ungraded_codes))
        if cover is None:
            print("no tests/fixtures in the repository around this skill - rule coverage "
                  "unmeasured (an installed copy carries no corpus)")
        else:
            countable = len(RULES) - len(no_engine)
            have = countable - len(untested)
            print(f"golden corpus: {have}/{countable} rules have a positive fixture"
                  + (f" · {', '.join(sorted(no_engine))} has no engine yet"
                     if no_engine else ""))
            if untested:
                print("  never observed firing: " + ", ".join(untested))
        if not orphan and not unused and not ungraded_codes:
            print(f"registry and engines agree · {len(RULES)} rules")
        return 1 if orphan or ungraded_codes else 0
    picked = [c for c in sorted(RULES) if not module or module_of(c) == module]
    if fmt == "json":
        print(json.dumps([RULES[c].as_dict() for c in picked], ensure_ascii=False, indent=2))
        return 0
    for code in picked:
        row = RULES[code]
        print(f"{code}  {row.severity:<7}  {module_of(code):<9}  {row.confidence:<7}"
              f"fp:{row.false_positive_risk:<7}{row.title}"
              + ("  [fixable]" if row.fixable else ""))
    return 0


# One line, not a block scalar: a scaffold that trips its own linter teaches the wrong
# thing on the first run.
QUERY_TEMPLATE = [
    {"query": "TODO a realistic prompt that should reach this skill, in the words a "
              "human would actually type - file paths, a bit of backstory, the odd typo",
     "should_trigger": True},
    {"query": "TODO a near-miss: shares vocabulary with the skill and needs something "
              "else. These are the ones that test precision", "should_trigger": False},
]

CASE_TEMPLATE = {
    "skill_name": "",
    "evals": [
        {"id": 1,
         "prompt": "TODO a realistic task for this skill",
         "expected_output": "TODO what success looks like, in a sentence",
         "assertions": ["TODO something checkable about the output"]},
    ],
}


def cmd_init_evals(skills):
    """Scaffold the two documented eval files for each named skill."""
    import json as _json
    made = 0
    for s in skills:
        d = os.path.join(s.root, "evals")
        os.makedirs(d, exist_ok=True)
        for rel, payload in (("eval_queries.json", QUERY_TEMPLATE),
                             ("evals.json", dict(CASE_TEMPLATE,
                                                 skill_name=s.name or s.folder))):
            path = os.path.join(d, rel)
            if os.path.exists(path):
                print(f"{s.folder}: evals/{rel} already exists, left alone")
                continue
            with open(path, "w", encoding="utf-8") as f:
                _json.dump(payload, f, ensure_ascii=False, indent=2)
                f.write("\n")
            print(f"{s.folder}: wrote evals/{rel}")
            made += 1
    if made:
        print("\nFill the TODOs, then `sqs.py eval <skill> --trigger`. Aim for about "
              "twenty queries,\neight to ten on each side; the negatives are what test "
              "precision.")
    return 0


def cmd_cases(skills, cfg, since, apply_it, fmt="text"):
    """`sqs.py cases <skill> --generate` - the case set the skill's own sources ask for.

    Every expensive layer here needs a case set and none of them helps you write one.
    This writes the first draft out of the three sources that can be read without an
    agent: the expectations you wrote beside the skill, the outcomes its description
    commits to, and - with `--since` - the capabilities it gained since then.

    It is a draft on purpose. Every case carries `needs_review`, an assertion appears
    only where the source named something checkable, and the rest is `TODO`: a case
    that passes without having tested anything is the one output the grader already
    refuses to produce, and generating a heap of them would be worse than the empty
    `evals/` it replaced.
    """
    import tempfile
    payloads = []
    for s in skills:
        if not s.ok:
            continue
        gained = []
        if since:
            with tempfile.TemporaryDirectory() as tmp:
                old_root = publish.previous_copy(s, since, tmp)
                if old_root:
                    gained = caseset.gained_capabilities(
                        s, capabilities.check(Skill(old_root), cfg), cfg)
        payloads.append((s, caseset.generate(s, gained)))

    if fmt == "json":
        print(json.dumps({s.folder: p for s, p in payloads}, ensure_ascii=False, indent=2))
        return 0

    rc = 0
    for s, payload in payloads:
        by_source = {}
        for c in payload["evals"]:
            by_source.setdefault(c["source"], []).append(c)
        print(f"\n{s.folder}: {len(payload['evals'])} case(s) drafted")
        for source in ("expectation", "promise", "improvement"):
            for c in by_source.get(source, []):
                print(f"  {source:<12} {c['id']:<22} {c['prompt'][:56]}")
        if not payload["evals"]:
            print(f"  nothing to draft - no {caseset.EXPECTATIONS}, and the description "
                  f"commits to no outcome a pattern can see")
            continue
        target = os.path.join(s.root, caseset.CASES_FILE.replace("/", os.sep))
        if not apply_it:
            print(f"  would write {caseset.CASES_FILE} (pass --apply)")
            rc = 1
            continue
        if os.path.exists(target):
            print(f"  {caseset.CASES_FILE} already exists - left alone. Generated is not "
                  f"trusted, and overwriting a set somebody corrected would prove it")
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print(f"  wrote {caseset.CASES_FILE}")
    print("\nEvery case is a draft: fill the TODOs before `sqs.py eval --runtime` means "
          "anything.\nA case with no assertion and no output is ungraded and stays that way "
          "in the report.")
    return rc


def cmd_cases_history(skills, history_dir, apply_it, fmt="text"):
    """`sqs.py cases <skill> --from-history` - trigger queries in the user's own words.

    A trigger set the author writes tends to restate the description; the phrasings that
    test it are the ones people typed. This drafts `evals/eval_queries.json` out of the
    local transcripts - see `evaluation/history.py` for what counts as a routing
    decision - prints it for review, and writes it only with `--apply`, only where the
    skill has no trigger set yet. What it prints is private: the user's own prompts.
    """
    from evaluation import history, triggers  # noqa: PLC0415
    rc = 0
    results = {}
    for s in skills:
        if not s.ok:
            continue
        h = history.harvest(s, history_dir)
        results[s.folder] = h
        if fmt == "json":
            continue
        print(f"\n{s.folder}: {len(h['positive'])} prompt(s) that loaded it first, "
              f"{len(h['near_miss'])} near miss(es) a neighbour won "
              f"({h['transcripts']} transcripts read)")
        for p in h["positive"]:
            print(f"  +  {' '.join(p.split())[:90]}")
        for n in h["near_miss"]:
            print(f"  -  {' '.join(n['query'].split())[:70]}   -> {n['went_to']}")
        target = os.path.join(s.root, "evals", "eval_queries.json")
        existing = [q for q in (target, os.path.join(s.root, triggers.TRIGGER_DIR))
                    if os.path.exists(q)]
        if not h["positive"] and not h["near_miss"]:
            continue
        if not apply_it:
            print("  would write evals/eval_queries.json (pass --apply) - these are your own "
                  "words; read them before they go anywhere")
            rc = 1
            continue
        if existing:
            print(f"  a trigger set already exists ({os.path.relpath(existing[0], s.root)}) "
                  f"- left alone; merge by hand")
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "w", encoding="utf-8") as f:
            json.dump(history.as_query_set(h), f, ensure_ascii=False, indent=2)
            f.write("\n")
        print("  wrote evals/eval_queries.json")
    if fmt == "json":
        print(json.dumps(results, ensure_ascii=False, indent=2))
    return rc


def cmd_eval(skills, root, a, cfg):
    """The layer that runs an agent: triggering, task success, and the diff between runs.

    Split from `check` on purpose. Everything under `check` is free, offline and
    deterministic; everything here costs money, needs an agent installed and gives a
    slightly different answer every time. Folding the two together would make the
    cheap half hostage to the expensive one.
    """
    from evaluation import environment, providers, regression, runtime, triggers  # noqa: PLC0415

    if not skills:
        print("eval takes a skill: `sqs.py eval ./my-skill --trigger`", file=sys.stderr)
        return 2

    want_trigger = a.trigger or a.all_layers
    want_runtime = a.runtime or a.all_layers
    fmt_json = a.format == "json"

    if a.compare:
        rc = 0
        for s in skills:
            name = s.name or s.folder
            if len(a.compare) != 2:
                print("--compare takes two labels, e.g. `--compare v1 v2`", file=sys.stderr)
                return 2
            before, after = (regression.load(root, name, lbl) for lbl in a.compare)
            if before is None or after is None:
                have = regression.labels(root, name)
                print(f"{name}: no stored run for "
                      f"{a.compare[0] if before is None else a.compare[1]}"
                      + (f" - stored: {', '.join(have)}" if have else
                         " - nothing stored yet; `--save <label>` records a run"),
                      file=sys.stderr)
                rc = max(rc, 2)
                continue
            diff = regression.compare(before, after)
            diff["skill"] = name
            # with neighbours in the run there is more than one block, and an unnamed one
            # says a recall fell without saying whose
            head = f"{name}\n" if len(skills) > 1 else ""
            print(json.dumps(diff, ensure_ascii=False, indent=2) if fmt_json
                  else head + regression.render(diff, a.fail_on_cost))
            if regression.failed(diff, a.fail_on_cost):
                rc = max(rc, 1)
        return rc

    if not (want_trigger or want_runtime):
        # No layer chosen. Running both by default would spend money nobody asked to
        # spend, and a prompt is not an option: these commands run in hooks and CI,
        # where nothing is there to answer it.
        for s in skills:
            queries, qproblem = triggers.load(s.root)
            from evaluation import tasks as taskmod
            task_list, tproblem = taskmod.load(s.root)
            env, eproblem = environment.load(s.root, a.env)
            runs = environment.resolve(env or {}, runs=a.runs)["runs"]
            print(f"{s.folder}:" + (f"  (environment `{env['name']}`)"
                                    if env and env.get("name") else ""))
            if eproblem:
                print(f"    environment  {eproblem}")
            print(f"    trigger  {len(queries)} quer(y/ies) x {runs} runs"
                  if not qproblem else f"    trigger  {qproblem}")
            print(f"    runtime  {len(task_list)} task(s) x {runs} runs x 2 sides"
                  if not tproblem else f"    runtime  {tproblem}")
        print("\nPick a layer: --trigger, --runtime, or --all. Each one runs the agent, "
              "which costs\nmoney and minutes, so nothing runs until you name it.",
              file=sys.stderr)
        return 2

    engines = {}                       # provider name -> (provider, why), built once each

    def note(*parts):
        if not a.quiet and not fmt_json:
            print(*parts, file=sys.stderr)

    rc = 0
    for s in skills:
        name = s.name or s.folder
        env, problem = environment.load(s.root, a.env)
        if problem:
            print(f"{s.folder}: {problem}", file=sys.stderr)
            rc = max(rc, 2)
            continue
        run_cfg = environment.resolve(env, provider=a.provider,
                                      model=cfg.get("live_model") or a.model, runs=a.runs)
        if run_cfg["provider"] not in engines:
            engines[run_cfg["provider"]] = providers.get(run_cfg["provider"])
        provider, why = engines[run_cfg["provider"]]
        if provider is None or why:
            print(f"{s.folder}: {why or 'no provider ' + run_cfg['provider']}", file=sys.stderr)
            rc = max(rc, 2)
            continue
        runs, model = run_cfg["runs"], run_cfg["model"]
        # which environment measured this, kept with the run: `--compare` says so when two
        # runs came from different ones
        payload = {"skill": name, "environment": run_cfg}
        blocks = []

        if want_trigger:
            note(f"{name}: trigger pass, {runs} run(s) per query - this costs money")
            report, problem = triggers.evaluate(
                s, provider, runs=runs, model=model, use_split=not a.no_split)
            if problem:
                print(f"{s.folder}: {problem}", file=sys.stderr)
                rc = max(rc, 2)
            else:
                payload["trigger"] = report
                blocks.append(triggers.render(report))
                for block in report["sets"].values():
                    m = block["metrics"]
                    if m["false_positive"] or m["false_negative"]:
                        rc = max(rc, 1)

        # a neighbour is here for its trigger set; its tasks are not what was edited
        if want_runtime and s.root not in getattr(a, "neighbour_roots", ()):
            note(f"{name}: runtime pass, {runs} run(s) per task"
                 + (" x 2 sides" if not a.no_baseline else "") + " - this costs money")
            report, problem = runtime.evaluate(
                s, provider, runs=runs, model=model,
                with_baseline=not a.no_baseline,
                task_filter=set(a.task) if a.task else None, trusted=a.trust_target)
            if problem:
                print(f"{s.folder}: {problem}", file=sys.stderr)
                rc = max(rc, 2)
            else:
                payload["runtime"] = report
                blocks.append(runtime.render(report))
                treatment = report["sides"]["treatment"]
                if treatment.get("failed_runs"):
                    rc = max(rc, 2)
                success = treatment.get("success_rate")
                if success is not None and success < 1.0:
                    rc = max(rc, 1)

        if fmt_json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            print(("\n\n" + "-" * 60 + "\n\n").join(blocks))

        label = a.save or ("baseline" if a.baseline else None)
        if label and len(payload) > 2:
            path = regression.save(root, name, label, payload)
            note(f"{name}: saved as `{label}` in {path}")
    return rc


def cmd_harnesses(world, verbose=False):
    """The adapter registry: what a `--harness` name can be, and what it rests on."""
    for a in world:
        support = {True: "skills", False: "no skills", None: "undocumented"}[a.supports_skills]
        # when the row was last read against its page: a table without it cannot show it
        # has gone stale, and pages here move (four of ten in the first check)
        checked = f"checked {a.checked}" if a.checked else "never checked"
        print(f"{a.name:<14}{a.title:<16}{support:<14}{checked:<22}{a.docs}")
        if verbose:
            for loc in a.locations:
                print(f"    {loc}")
            if a.discovery:
                print(f"    discovery: {a.discovery}")
            for note in a.notes:
                print(f"    note: {note}")
            print()
    if not verbose:
        print(f"\n{len(world)} harnesses · `--harness <name>` or `--harness all` · "
              f"`sqs.py harnesses --show` for locations and caveats")
    return 0


ROUTE_CAVEAT = ("offline reasoning over descriptions, not a live run - `eval --trigger` "
                "is the thing that actually sends the wording to the agent and can "
                "disagree with this")


def nearest_neighbours(skill, tree, n):
    """[(score, skill)] - the `n` skills whose descriptions share most with this one's.

    Only skills with a trigger set of their own count: a neighbour is here to be
    measured, and one without queries cannot be. The comparison is `route`'s, run with
    this description standing in for the prompt - the requests a widened description
    would take are the ones worded like it.
    """
    from evaluation import triggers                                 # noqa: PLC0415
    own = quality.stems(skill.description or "")
    rows = []
    for s in tree:
        if s.root == skill.root or not s.ok or s.slash_only or not s.description:
            continue
        if triggers.load(s.root)[1]:
            continue
        score, _ = quality.prompt_match(s.description, own)
        if score > 0:
            rows.append((score, s))
    rows.sort(key=lambda r: -r[0])
    return rows[:n]


def cmd_route(skills, prompt, fmt="text"):
    """`sqs.py route --prompt "..."` - the offline, weaker sibling of `eval --trigger`.

    `eval --trigger` runs the agent and observes which skill it actually reaches for.
    This reasons about the descriptions instead: the same stem-overlap comparison `EV007`
    runs between two skills, run here between the prompt and every sentence of each
    skill's description, keeping the best-matching sentence per skill so the report can
    name it - a score with nothing to point at is unactionable, the same complaint that
    shaped `EV007`. It is cheaper and it can be wrong in a way the live pass would not
    be, so `ROUTE_CAVEAT` prints in every render rather than once in a docstring nobody
    reads at the terminal.

    The comparison itself is `quality.prompt_match`, which carries the calibration -
    `stems()` rather than `EV007`'s `content_stems()`, and exclusion clauses dropped -
    and which `cases` now runs an expectation through to ask the same question about a
    sentence the author wrote instead of one a user typed.
    """
    prompt_stems = quality.stems(prompt)
    rows = []
    for s in skills:
        if not s.ok or s.slash_only or not s.description:
            continue
        best_score, best_sentence = quality.prompt_match(s.description, prompt_stems)
        rows.append((s.name or s.folder, best_score, best_sentence))
    rows.sort(key=lambda r: r[1], reverse=True)

    if fmt == "json":
        print(json.dumps({"prompt": prompt, "caveat": ROUTE_CAVEAT,
                          "ranking": [{"skill": n, "score": round(sc, 3), "matched": sent}
                                     for n, sc, sent in rows]},
                         ensure_ascii=False, indent=2))
        return 0

    print(f'route: "{prompt}"')
    print(f"({ROUTE_CAVEAT})\n")
    scored = [r for r in rows if r[1] > 0]
    if not scored:
        print("no skill's description shares enough wording with this prompt to rank.")
        return 0
    for i, (name, score, sentence) in enumerate(scored[:10], 1):
        print(f"{i}. {name:<28}{score:.2f}  \"{sentence[:70]}\"")
    if len(scored) > 1:
        margin = scored[0][1] - scored[1][1]
        print(f"\n`{scored[0][0]}` wins by {margin:.2f} over `{scored[1][0]}`")
    return 0


def cmd_compat_report(skills, world, names, fmt):
    """The compatibility report: the one view that is per harness, not per finding."""
    adapters, missing = world.select(names)
    for m in missing:
        print(f"no adapter for `{m}` - known harnesses are {', '.join(world.names())}",
              file=sys.stderr)
    if not adapters:
        return 2
    blobs, worst = [], 0
    for s in skills:
        model = SkillModel(s, world)
        results = portability.analyse(model, adapters, world)
        if fmt == "json":
            blobs.append(portability.report_json(model, results))
        else:
            blobs.append(portability.report_text(model, results))
        if any(r.verdict == portability.INCOMPATIBLE for r in results):
            worst = 1
    if fmt == "json":
        print(json.dumps(blobs if len(blobs) > 1 else blobs[0],
                         ensure_ascii=False, indent=2))
    else:
        print(("\n\n" + "-" * 60 + "\n\n").join(blobs))
    return worst


TEMPLATE = """---
name: {name}
description: TODO one sentence on what this skill is, then the branches that should trigger it - the wordings a human actually uses, one per distinct branch, because synonyms that rename one branch are one branch written twice.
---

# {title}

TODO the steps, in the order the agent performs them. Each one ends on a condition the
agent can check: "every modified model accounted for", not "understanding reached".

## When to open which reference

TODO name each reference and the branch that reaches it. Material every branch needs
stays here; material only some branches reach goes into references/ behind a pointer.
"""


PAID_OFFER = ("Not run, and not run without your say-so: `eval --trigger` measures what "
              "actually loads, at about $0.21 per run (measured 23.09.2026) and sixty runs "
              "for a proper set. It pays off only over time - repeated across edits, "
              "against the last saved run - not as one number today.")
JUDGE_OFFER = ("Whether it was followed to the end - the step skipped in silence, the check "
               "left out before \"done\" - no count here can see: `improve <skill> "
               "--transcripts DIR` writes its latest loads for free, and reading them "
               "against references/judging-sessions.md is a model's work, paid from your "
               "usage window in proportion to the characters written.")


def cmd_improve(skills, results, history_dir, fmt="text", journal_dir=None,
                transcripts_dir=None, max_loads=12):
    """`sqs.py improve <skill>` - what to change, from the skill and from your requests.

    Two sources, and only what each can say reliably. The skill itself: every finding,
    grouped by what to fix first, with the fix the registry already states. Your
    requests: the prompts that really routed to it, and the ones a neighbour won that
    this skill's description also covers - read off the transcripts, the way
    `cases --from-history` does.

    What it does not do is judge intent. Whether a prompt nothing loaded for was *meant*
    for this skill is a question stems cannot answer - tried on 1,058 real prompts, and
    the "missed" list was mostly conversation, not requests. That judgement belongs to a
    model, which is paid, so it is offered at the end and never started from here.
    """
    from evaluation import history  # noqa: PLC0415
    import journal  # noqa: PLC0415
    findings = dict(results)
    report = {}
    for s in skills:
        if not s.ok:
            continue
        fs = findings.get(s.folder, [])
        by_code = {}
        for f in fs:
            by_code.setdefault(f.code, []).append(f)
        fix = []
        for code, group in by_code.items():
            rule = RULES.get(code)
            fix.append({"code": code, "severity": group[0].severity, "count": len(group),
                        "title": rule.title if rule else "", "fix": rule.how if rule else "",
                        "example": group[0].msg})
        fix.sort(key=lambda r: (RANK.get(r["severity"], 3), r["code"]))
        h = history.harvest(s, history_dir, limit=1000)
        report[s.folder] = {"fix": fix, "work": history.work_after_load(s, history_dir),
                            "ran_unloaded": history.ran_unloaded(s, history_dir),
                            "journal": journal.for_skill(s, journal_dir) if journal_dir
                            else None,
                            "routed_here": len(h["positive"]),
                            "examples": h["positive"][:5],
                            "neighbours_won": h["near_miss"][:5],
                            "has_trigger_set": os.path.exists(
                                os.path.join(s.root, "evals", "eval_queries.json"))
                            or os.path.isdir(os.path.join(s.root, "evals", "trigger")),
                            "paid_offer": PAID_OFFER, "judge_offer": JUDGE_OFFER}
        if transcripts_dir:
            from evaluation import transcripts  # noqa: PLC0415
            got = transcripts.collect(s, history_dir, max_loads)
            report[s.folder]["transcripts"] = dict(
                transcripts.write(got, transcripts_dir), found=got["found"],
                written=len(got["loads"]), skipped_building=got["skipped_building"],
                versions={v["label"]: v["same_as_current"] for v in got["versions"].values()})
    if fmt == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    for folder, r in report.items():
        print(f"\n{folder}")
        serious = [x for x in r["fix"] if x["severity"] in ("error", "warning")]
        minor = [x for x in r["fix"] if x not in serious]
        print("  1. Fix first" if serious else "  1. Nothing to fix first")
        for x in serious:
            times = f" x{x['count']}" if x["count"] > 1 else ""
            print(f"     {x['code']}{times}  {x['title']}")
            print(f"            {x['example'][:100]}")
            print(f"            fix: {x['fix'][:160]}")
        if minor:
            print(f"     and {len(minor)} note(s): " + ", ".join(x["code"] for x in minor)
                  + " - `sqs.py explain <CODE>` for each")
        print(f"  2. What your requests say - {r['routed_here']} prompt(s) in your history "
              f"loaded it first")
        for p in r["examples"]:
            print(f"     +  {' '.join(p.split())[:90]}")
        if r["neighbours_won"]:
            print("     a neighbour won these; this description shares words with them, "
                  "closest first - check the boundary on the top ones:")
            for n in r["neighbours_won"]:
                print(f"     -  {' '.join(n['query'].split())[:70]}   -> {n['went_to']}")
        _print_unloaded(r["ran_unloaded"])
        if not r["has_trigger_set"] and (r["routed_here"] or r["neighbours_won"]):
            print("     no trigger set yet: `sqs.py cases <skill> --from-history --apply` "
                  "drafts one from exactly these")
        _print_work(r["work"])
        _print_journal(r["journal"])
        print(f"  5. Paid, only if you want it. {r['paid_offer']}")
        print(f"     {r['judge_offer']}")
        if "transcripts" in r:
            _print_transcripts(r["transcripts"])
    return 0


def _print_transcripts(t):
    """Section 6 of `improve`: the loads written for a judge, and what reading them costs."""
    print(f"  6. For a judge - {t['written']} of {t['found']} load(s) written to {t['dir']}"
          + (f", {t['skipped_building']} left out from sessions that edited the skill"
             if t["skipped_building"] else ""))
    if not t["written"]:
        return
    stale = [k for k, same in t["versions"].items() if not same]
    print(f"     {t['chars']} characters to read; secrets masked. Judge only on a yes, by "
          f"references/judging-sessions.md")
    if stale:
        print(f"     {', '.join(stale)} loaded a text that is not the current SKILL.md: a "
              f"failure there may already be fixed - check it against the file before "
              f"proposing anything")


def _print_unloaded(u):
    """Part of section 2 of `improve`: its own scripts, run while it was never loaded."""
    if not u["turns"]:
        return
    print(f"     its own scripts ran in {u['turns']} turn(s) of {u['sessions']} session(s) "
          f"that never loaded it - the description did not fire, or something else (a "
          f"CLAUDE.md, a hook, a memory) sends the agent straight to the script:")
    for x in u["examples"]:
        print(f"     ~  {' '.join(x['prompt'].split())[:70]}   ran {', '.join(x['scripts'])}")


def cmd_discover(skills, history_dir, fmt="text", journal_dir=None):
    """`sqs.py discover` - what the history says to build or to fix, across the tree.

    Two readings of the agent's own actions, never of the wording alone, which was
    measured as noise: the skills whose scripts ran in sessions that never loaded them
    (a routing miss, or an instruction elsewhere doing the routing), and the work
    repeated across sessions with no skill in context (a candidate for a new skill). It
    decides nothing: the prompts behind each row are printed so a reader - the agent
    running this, or the person - judges whether the rows are one task.
    """
    from evaluation import history  # noqa: PLC0415
    names = {s.folder for s in skills} | {s.name for s in skills if s.name}
    unloaded = {k: v for k, v in history.unloaded_by_skill(history_dir).items() if k in names}
    work = history.unskilled_work(history_dir)
    import journal  # noqa: PLC0415
    named, total = journal.per_skill(skills, journal_dir) if journal_dir else ({}, 0)
    if fmt == "json":
        print(json.dumps({"ran_unloaded": {k: {"turns": t, "sessions": n}
                                           for k, (t, n) in unloaded.items()},
                          "unskilled_work": work,
                          "journal": {"dir": journal_dir, "entries": total,
                                      "skills": {k: {"entries": c, "open": o}
                                                 for k, (c, o) in named.items()}}},
                         ensure_ascii=False, indent=2))
        return 0
    print("1. Skills whose own scripts ran in sessions that never loaded them")
    if not unloaded:
        print("   none - every script run from a skill folder came after that skill loaded")
    for k, (t, n) in sorted(unloaded.items(), key=lambda kv: (-kv[1][0], kv[0])):
        print(f"   {t:4} turn(s) in {n:3} session(s)  {k}")
    if unloaded:
        print("   `sqs.py improve <skill>` lists the prompts behind each: should-trigger "
              "wordings, unless an instruction outside the skill is doing the routing")
    print()
    print("2. Work repeated across sessions with no skill loaded")
    if not work:
        print("   nothing repeated in two or more sessions")
    for w in work:
        verb = "ran" if w["kind"] == "script" else "edited"
        where = (f"1 project ({w['projects'][0][-40:]})" if len(w["projects"]) == 1
                 else f"{len(w['projects'])} projects")
        print(f"   {w['sessions']:3} session(s), {w['turns']:3} turn(s), {where}  "
              f"{verb} {w['what']}")
        for p in w["prompts"]:
            print(f"          {p[:90]}")
    if work:
        print("   Read the prompts before deciding: rows can be one task or several, and a "
              "document edited often may already belong to a skill that did not fire. For "
              "a task worth a skill: `sqs.py new <name> --seed <word>`, then "
              "references/creating-a-skill.md.")
    print()
    print("3. Skills your mistakes journal names")
    if not journal_dir:
        print("   no journal configured: `mistakes` in sqs.config.json or --mistakes-dir")
    elif not named:
        print(f"   none of {total} entries names a skill here")
    for k, (c, o) in sorted(named.items(), key=lambda kv: (-kv[1][0], kv[0])):
        print(f"   {c:3} entr{'y ' if c == 1 else 'ies'} ({o} not reviewed)  {k}")
    if named:
        print(f"   of {total} entries in all. `sqs.py improve <skill>` prints their patterns; "
              f"{journal.LADDER}.")
    return 0


def _print_journal(j):
    """Section 4 of `improve`: what the mistakes journal says about the skill."""
    import journal  # noqa: PLC0415
    if j is None:
        print("  4. Mistakes journal - none configured: `mistakes` in sqs.config.json or "
              "--mistakes-dir; see references/mistakes-journal.md")
        return
    if not j["count"]:
        print(f"  4. Mistakes journal - no entry names it ({j['journal']})")
        return
    print(f"  4. Mistakes journal - {j['count']} entr{'y' if j['count'] == 1 else 'ies'} "
          f"name it, {j['open']} not reviewed yet. The ladder: {journal.LADDER}.")
    print("     Read the patterns, not the count: entries about one skill are often "
          "different mistakes.")
    for e in j["entries"]:
        mark = "reviewed" if e["reviewed"] else "open"
        print(f"     {e['date'] or '?':10} {mark:8} {e['pattern'][:120]}")


def _print_work(w):
    """Section 3 of `improve`: where the agent's work went after the skill loaded."""
    if not w.get("loads"):
        print("  3. Where the work went - it never loaded in your history")
        return
    print(f"  3. Where the work went - {w['loads']} load(s) in {w['sessions']} session(s), "
          f"median {w['median_fresh_tokens']} fresh input and {w['median_output_tokens']} "
          f"output tokens a load")
    print("     counted from the load to your next message, so a turn that moved on to "
          "other work is in here too")
    for x in w["lookups"]:
        print(f"     looked up again in {x['sessions']} sessions - write the answer into "
              f"the skill:")
        print(f"        {x['command'][:110]}")
    for x in w["heavy_reads"]:
        print(f"     read in full: {x['chars']} chars over {x['reads']} read(s) - a grep, "
              f"a section or a script would do: {x['file'][-80:]}")
    for x in w["rereads"]:
        print(f"     read again with no edit between: {x['times']}x {x['file'][-80:]}")
    for x in w.get("failures", []):
        print(f"     failed again in {x['sessions']} sessions - fix the step that leads there: "
              f"{x['call']}")
        print(f"        last error: {x['last_error'][:110]}")
    stop = w.get("interrupted") or {}
    if stop.get("loads"):
        base = (f"{stop['base_stopped']} of {stop['base_turns']} turns with no skill"
                if stop.get("base_turns") else "no baseline")
        print(f"     you stopped it in {stop['loads']} of {w['loads']} loads ({base}) - "
              f"look at what it was doing when you did")


def cmd_new_seeded(seeds, history_dir):
    """`sqs.py new <name> --seed WORD ...` - what you already ask that it would take.

    A skill that does not exist yet has no loads to learn from, so the user names a few
    words it would be asked with, and this shows the prompts in their history that carry
    them - and which skill each one reached instead. Most of them landing on one existing
    skill is the finding: that skill may want a new branch rather than a new neighbour.
    """
    from evaluation import history  # noqa: PLC0415
    hits = history.search(seeds, history_dir)
    print(f"\n{len(hits)} prompt(s) in your history carry {', '.join(seeds)}")
    if not hits:
        print("  nothing to learn from yet - write the description from a real run of the "
              "work, and `cases --from-history` will find its first routes later")
        return
    unrouted = "(first action was not a skill - mostly mid-conversation)"
    went = {}
    for p, loaded in hits:
        went.setdefault(loaded or unrouted, []).append(p)
    for target, ps in sorted(went.items(), key=lambda kv: -len(kv[1])):
        print(f"  {len(ps):3}  {'went to ' + target if target != unrouted else target}")
        for p in ps[:3]:
            print(f"         {' '.join(p.split())[:80]}")
    # The advice counts only the prompts that did reach a skill: the rest were said in the
    # middle of other work, and a majority of those says nothing about routing. Two is the
    # floor, because one prompt going somewhere is an anecdote.
    routed = {k: v for k, v in went.items() if k != unrouted}
    total = sum(len(v) for v in routed.values())
    if routed:
        top, ps = max(routed.items(), key=lambda kv: len(kv[1]))
        if len(ps) >= 2 and len(ps) * 2 > total:
            print(f"  Of the {total} that reached a skill, {len(ps)} reached `{top}`. Before "
                  f"adding a neighbour, ask whether `{top}` needs a new branch instead - two "
                  f"skills claiming one wording is the collision `EV007` reports.")
    print("  These are candidate trigger wordings in your own words: read them before any "
          "of them goes into the new description or its trigger set.")


def cmd_new(root, name):
    target = os.path.join(root, name)
    if os.path.exists(target):
        print(f"{target} already exists", file=sys.stderr)
        return 2
    os.makedirs(os.path.join(target, "references"))
    with open(os.path.join(target, "SKILL.md"), "w", encoding="utf-8") as f:
        f.write(TEMPLATE.format(name=name, title=name.replace("-", " ").capitalize()))
    print(f"created {target}/SKILL.md")
    print("Next: fill it from a real run of the work, not from an idea of the work, then")
    print(f"      python {os.path.relpath(__file__, os.getcwd())} check {name}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sqs.py", add_help=True,
                                 description="quality suite for Agent Skills")
    ap.add_argument("command", help="check | all | " + " | ".join(sorted(MODULES.values()))
                    + " | fix | eval | baseline | explain | rules | harnesses | new | route"
                    + " | improve | discover")
    ap.add_argument("args", nargs="*", help="skill names, a rule code, or a new skill's name")
    ap.add_argument("--skills-dir")
    ap.add_argument("--trust-target", action="store_true",
                    help="the tree is yours: let its own evals/run_evals.py run, "
                         "and let `eval --runtime` run a skill "
                         "that can reach the network or spawn processes. Off by default "
                         "- reading a skill is not a reason to execute one")
    ap.add_argument("--config")
    ap.add_argument("--format", choices=("text", "json", "github", "sarif", "board"),
                    default="text", help="sarif for code-scanning, board for the layer view")
    ap.add_argument("--score", action="store_true",
                    help="add the aggregate number, with the arithmetic that produced it")
    ap.add_argument("--min-confidence", choices=("low", "medium", "high"),
                    help="drop findings the suite is less sure of than this")
    ap.add_argument("--baseline", action="store_true",
                    help="report only findings the baseline does not already carry")
    ap.add_argument("--baseline-file", help="where the baseline lives (default .sqs-baseline.json)")
    ap.add_argument("--changed", action="store_true",
                    help="only skills touched by the git diff against --since")
    ap.add_argument("--since", help="the earlier state to compare against: a git ref, or a "
                                    "directory holding an earlier copy of the tree. Selects "
                                    "the skills for --changed, and is what PB010-PB013 read "
                                    "the previous version off (default HEAD for --changed, "
                                    "and PB010-PB013 stay off until it is given)")
    ap.add_argument("--strict", action="store_true", help="warnings count as failures")
    ap.add_argument("--quiet", action="store_true", help="print nothing when clean")
    ap.add_argument("--harness", action="append", default=[],
                    help="target environment; repeatable, comma-separated, or `all`")
    ap.add_argument("--agents", help="deprecated alias for --harness")
    ap.add_argument("--show", action="store_true",
                    help="harnesses: locations, discovery and caveats for each")
    ap.add_argument("--lang", help="the language the published docs are written in")
    ap.add_argument("--trigger", action="store_true",
                    help="eval: run the agent against the trigger set (costs money)")
    ap.add_argument("--runtime", action="store_true",
                    help="eval: run the task set with the skill and without it (costs money)")
    ap.add_argument("--all", dest="all_layers", action="store_true",
                    help="eval: both layers")
    ap.add_argument("--provider", help="eval: which agent to drive (default: the "
                    "environment's, else claude)")
    ap.add_argument("--env", help="eval: the environment in evals/environment.json to run "
                    "in (default: its `default`, if it has one)")
    ap.add_argument("--model", help="eval: model for the runs")
    ap.add_argument("--task", action="append", default=[], help="eval: only this task id")
    ap.add_argument("--no-baseline", action="store_true",
                    help="eval: skip the without-the-skill arm; halves the cost and the meaning")
    ap.add_argument("--save", help="eval: store the run under this label for later comparison")
    ap.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"),
                    help="eval: diff two stored runs")
    ap.add_argument("--fail-on-cost", action="store_true",
                    help="eval --compare: a cost rise fails the gate too")
    ap.add_argument("--init", action="store_true",
                    help="evals: scaffold the two documented eval files")
    ap.add_argument("--runs", type=int,
                    help="eval: runs per query or per task; the model is not deterministic "
                         "(default: the environment's, else 3)")
    ap.add_argument("--no-split", action="store_true",
                    help="eval --trigger: measure one set instead of train/validation")
    ap.add_argument("--with-neighbours", type=int, default=0, metavar="N",
                    help="eval --trigger: also run the N skills whose descriptions share "
                         "most with this one, so --compare shows whether an edit took "
                         "their requests")
    ap.add_argument("--live", action="store_true", help="evals: ask the model, not the invariants")
    ap.add_argument("--apply", action="store_true", help="fix: write the repairs")
    ap.add_argument("--module", help="rules: only this module")
    ap.add_argument("--audit", action="store_true", help="rules: registry against the engines")
    ap.add_argument("--prompt", help="route: the wording to reason about")
    ap.add_argument("--generate", action="store_true",
                    help="cases: draft the case set instead of reporting on it")
    ap.add_argument("--from-history", action="store_true",
                    help="cases: draft trigger queries from your own Claude Code transcripts "
                         "- prompts that loaded the skill, and near misses a neighbour won")
    ap.add_argument("--seed", action="append", default=[],
                    help="new: a word the new skill would be asked with; shows the prompts in "
                         "your history that carry it and where they went (repeatable)")
    ap.add_argument("--mistakes-dir", help="improve, discover: the mistakes journal folder "
                                           "(default: `mistakes` in sqs.config.json)")
    ap.add_argument("--history-dir", help="cases --from-history: where the transcripts are "
                                          "(default ~/.claude/projects)")
    ap.add_argument("--transcripts", metavar="DIR",
                    help="improve: also write the skill's latest loads to DIR, masked, for a "
                         "model to judge against references/judging-sessions.md. Writing is "
                         "free; the judging is paid, and never starts from here")
    ap.add_argument("--max-loads", type=int, default=12,
                    help="improve --transcripts: how many of the latest loads (default 12)")
    a = ap.parse_args(argv)

    if a.command == "explain":
        return cmd_explain(a.args[0], a.format) if a.args else cmd_rules()
    if a.command == "rules":
        return cmd_rules(a.module, a.audit, a.format)
    world = harness_registry()
    if a.command == "harnesses":
        return cmd_harnesses(world, a.show)

    root = skills_dir(a.skills_dir)
    if not os.path.isdir(root):
        print(f"no skills directory at {root}", file=sys.stderr)
        return 2
    if a.command == "discover":
        return cmd_discover(discover(root), a.history_dir, a.format,
                            journal_dir(load_config(root, a.config), a.mistakes_dir))
    if a.command == "new":
        if not a.args:
            return 2
        rc = cmd_new(root, a.args[0])
        if rc == 0 and a.seed:
            cmd_new_seeded(a.seed, a.history_dir)
        return rc

    cfg = load_config(root, a.config)
    picked = []
    for chunk in list(a.harness) + ([a.agents] if a.agents else []):
        picked += [s.strip() for s in chunk.split(",") if s.strip()]
    if picked:
        cfg["harnesses"] = picked
    if a.lang:
        cfg["lang"] = a.lang
    # `--since` is resolved once, here, because the interesting half of the answer is
    # the failure: a ref nobody can find would otherwise leave PB010-PB013 silently
    # not running, and a rule that quietly did not run reads exactly like a rule that
    # found nothing.
    if a.since:
        spec, note = publish.resolve_since(a.since, root)
        if spec:
            cfg["since"] = spec
        if note and not a.quiet:
            print(note, file=sys.stderr)

    if a.command == "eval":
        names = [n for n in a.args if n not in set(cfg.get("ignore", []))]
        picked_skills, notes = resolve_targets(names, root)
        for note in notes:
            print(note, file=sys.stderr)
        a.neighbour_roots = set()
        if a.with_neighbours and names:
            have = {s.root for s in picked_skills}
            for s in list(picked_skills):
                for score, n in nearest_neighbours(s, discover(root), a.with_neighbours):
                    if n.root in have:
                        continue
                    have.add(n.root)
                    a.neighbour_roots.add(n.root)
                    picked_skills.append(n)
                    print(f"{s.folder}: neighbour `{n.folder}` joins the trigger pass "
                          f"(description overlap {score:.2f}) - its recall across your edit "
                          f"is what says whether this description took its requests; it "
                          f"adds its own queries x runs to the cost", file=sys.stderr)
            if not a.neighbour_roots:
                print("no neighbour with a trigger set of its own shares words with this "
                      "description - nothing to measure it against", file=sys.stderr)
        return cmd_eval(picked_skills, root, a, cfg)

    if a.command == "route":
        if not a.prompt:
            print("route needs --prompt \"...\"", file=sys.stderr)
            return 2
        names = [n for n in a.args if n not in set(cfg.get("ignore", []))]
        picked_skills, notes = resolve_targets(names, root)
        for note in notes:
            print(note, file=sys.stderr)
        return cmd_route(picked_skills, a.prompt, a.format)

    if a.command == "check":
        modules = list(CHECK_MODULES)
    elif a.command == "all":
        modules = list(CHECK_MODULES) + ["publish"]
    elif a.command == "baseline":
        modules = list(CHECK_MODULES)
    elif a.command == "improve":
        modules = list(CHECK_MODULES) + ["evals"]
    elif a.command in set(MODULES.values()) | {"fix"}:
        modules = [a.command]
    else:
        print(f"unknown command {a.command!r}", file=sys.stderr)
        return 2

    baseline_action = "create"
    if a.command == "baseline":
        if a.args and a.args[0] in ("create", "show"):
            baseline_action = a.args.pop(0)
        elif a.args:
            print(f"baseline takes `create` or `show`, not {a.args[0]!r}", file=sys.stderr)
            return 2

    ignore = set(cfg.get("ignore", []))
    names = [n for n in a.args if n not in ignore]
    skills, notes = resolve_targets(names, root)
    skills = [s for s in skills if s.folder not in ignore]
    if a.changed:
        skills, note = changed_skills(skills, a.since or "HEAD")
        if not a.quiet:
            print(note, file=sys.stderr)
    for note in notes:
        print(note, file=sys.stderr)
    # Neighbours are the installed skills plus the ones under examination. Building this
    # from `root` alone was right only while the two were the same tree: `root` follows
    # `--skills-dir`, not the positional target, so checking a directory somewhere else
    # left every skill in it a stranger to the others and the neighbour-aware rules
    # (`QL008`, `QL013`) read a named sibling as an unnamed topic.
    neighbours = list(discover(root)) + list(skills)
    skill_registry = {s.name or s.folder: s.slash_only for s in neighbours}
    # The same neighbours, by description rather than by invocation mode: `CS002` has
    # to be able to say *which* skill does promise the thing you expected, and "the
    # wrong skill" without naming the right one is half an answer.
    cfg["descriptions"] = {s.name or s.folder: s.description for s in neighbours}

    # `cases --generate` writes the set the rules would otherwise only report on.
    if a.command == "cases" and a.from_history:
        return cmd_cases_history(skills, a.history_dir, a.apply, a.format)
    if a.command == "cases" and a.generate:
        return cmd_cases(skills, cfg, cfg.get("since"), a.apply, a.format)

    # The compatibility report is a different view of the same analysis, not a
    # different analysis: per harness rather than per finding. `check --harness` still
    # folds the same verdicts into the ordinary report, so CI can fail on them.
    if a.command == "compat" and compat.harness_names(cfg) and skills:
        return cmd_compat_report(skills, world, compat.harness_names(cfg), a.format)

    # evals is a whole-tree check: it compares descriptions against each other, so it
    # has no per-skill form and runs once.
    eval_findings = []
    if a.command in ("evals", "all"):
        # Routing is a property of the whole tree, so it runs once rather than per skill.
        eval_findings = evals_findings(root, a.live, names, a.trust_target)

    # The trigger loop runs the agent, so it is opt-in and never part of `check`. It
    # lives under `eval` now, with the rest of the layer that costs money; the old
    # spelling still works because it is in people's hooks.
    if a.command == "evals" and a.trigger:
        print("`evals --trigger` is now `eval --trigger` - same run, and `eval` "
              "is where the runtime and regression passes live too.",
              file=sys.stderr)
        return cmd_eval(skills, root, a, cfg)

    if a.command == "evals" and a.init:
        return cmd_init_evals(skills)

    engine = load_structure_engine(root) if "structure" in modules else None

    if a.command == "fix":
        rc = 0
        for s in skills:
            entries = fixer.plan(s)
            if not entries:
                continue
            for code, what, _ in entries:
                print(f"{'fixed' if a.apply else 'would fix'}  {s.folder}  {code}  {what}")
            if a.apply:
                fixer.apply(s, entries)
            else:
                rc = 1
        if rc == 0 and not a.quiet:
            print("nothing to fix" if not a.apply else "done")
        return rc

    results = [(s.folder, collect(s, modules, cfg, skill_registry, engine, world))
               for s in skills]
    if a.command == "improve":
        return cmd_improve(skills, results, a.history_dir, a.format,
                           journal_dir(cfg, a.mistakes_dir), a.transcripts, a.max_loads)

    # A duplicate `name` is only visible from above: one skill shadows the other and
    # which one wins is not knowable in advance.
    by_name = {}
    for s in skills:
        by_name.setdefault(s.name or s.folder, []).append(s.folder)
    by_folder = {s.folder: s.root for s in skills}
    dupes = []
    for n, d in sorted(by_name.items()):
        if len(d) <= 1:
            continue
        f = Finding("ST014", f"`name: {n}` in {', '.join(d)} - one shadows the other",
                    severity="error", where="SKILL.md")
        # it belongs to a real file, so a report that anchors findings to lines - SARIF,
        # a CI annotation - has somewhere to put it
        f.skill, f.root = d[0], by_folder.get(d[0])
        dupes.append(f)

    # EV007 - the static sibling of EV001: two skills' trigger branches cover the same
    # wording, found by comparing descriptions instead of executing the tree's own
    # `run_evals.py`. Runs unconditionally, the way ST014 above does - it is a property
    # of the skills being checked together, not of one module.
    overlaps = quality.cross_overlap(skills)

    # Whole-tree findings never passed through `collect()`, so the config's `rules: {off
    # | severity}` and a line's `sqs-allow` waived every per-skill finding and silently
    # did nothing for these three - the escape hatch a "high false-positive risk" rule
    # like EV007 depends on. `suppressed()` needs the actual `Skill` the finding is
    # attached to, to read the line it names; `skills_by_folder` is that lookup.
    overrides = cfg.get("rules", {})
    skills_by_folder = {s.folder: s for s in skills}
    whole_tree = []
    for f in dupes + eval_findings + overlaps:
        if overrides.get(f.code) == "off":
            continue
        owner = skills_by_folder.get(f.skill)
        if owner and suppressed(owner, f):
            continue
        if f.code in overrides:
            f.severity = overrides[f.code]
        whole_tree.append(f)

    if whole_tree:
        results.append(("(all skills)", whole_tree))

    # A confidence floor filters by how much of the judgement is the machine's. It is
    # not a severity filter: `--min-confidence high` keeps the facts and drops the
    # heuristics, which is the gate you can leave switched on in CI.
    if a.min_confidence:
        results = [(folder, [f for f in found
                             if at_least(RULES[f.code].confidence if f.code in RULES
                                         else "unrated", a.min_confidence)])
                   for folder, found in results]

    baseline_note = ""
    if a.command == "baseline":
        action = baseline_action
        if action == "create":
            path, n = baseline_store.save(root, results, a.baseline_file)
            print(f"recorded {n} finding(s) in {path}")
            print("From here `sqs.py check --baseline` fails on new findings only. The "
                  "recorded ones stay\nin the file - it is a queue, not a bin.")
            return 0
        if action == "show":
            data = baseline_store.load(root, a.baseline_file)
            if not data:
                print(f"no baseline at {baseline_store.path_for(root, a.baseline_file)}",
                      file=sys.stderr)
                return 2
            print(f"{len(data['findings'])} finding(s) recorded {data.get('created', '?')}")
            for entry in sorted(data["findings"].values(),
                                key=lambda e: (e["code"], e["skill"], e["file"] or "")):
                place = f" ({entry['file']})" if entry.get("file") else ""
                print(f"  {entry['severity']:<8}{entry['code']}  {entry['skill']}"
                      f"  {entry['message'][:70]}{place}")
            return 0
    if a.baseline:
        data = baseline_store.load(root, a.baseline_file)
        if data is None:
            print(f"no baseline at {baseline_store.path_for(root, a.baseline_file)} - "
                  f"`sqs.py baseline create` writes one", file=sys.stderr)
            return 2
        # Not named `suppressed`: that name is the module-level line-waiver function,
        # and any local assignment to it anywhere in `main()` would shadow the function
        # for the whole body, including the call above this baseline branch.
        results, baseline_waived, fixed = baseline_store.split(results, data)
        baseline_note = baseline_store.summary(baseline_waived, fixed, data)

    flat = [f for _, found in results for f in found]
    failures = sum(1 for f in flat
                   if f.severity == "error" or (a.strict and f.severity == "warning"))

    if a.format == "json":
        print(report.render_json(results))
    elif a.format == "sarif":
        first = skills[0] if skills else None
        fallback = os.path.relpath(os.path.join(first.root, "SKILL.md"),
                                   os.getcwd()).replace(chr(92), "/") if first else None
        print(report.render_sarif(results, fallback=fallback))
    elif a.format == "github":
        out = report.render_github(results)
        if out:
            print(out)
    elif a.format == "board":
        extras = stored_eval_rows(root, skills)
        measured = {row[0] for row in extras}
        if "TRIGGER" not in measured:
            extras.append(("TRIGGER", "NOT RUN",
                           "`sqs.py eval <skill> --trigger` runs the agent"))
        if "RUNTIME" not in measured:
            extras.append(("RUNTIME", "NOT RUN",
                           "`sqs.py eval <skill> --runtime` runs the task set"))
        extras.sort(key=lambda row: ("TRIGGER", "RUNTIME", "REGRESSION").index(row[0])
                    if row[0] in ("TRIGGER", "RUNTIME", "REGRESSION") else 9)
        print(report.render_board(results, set(modules), extras))
        if baseline_note:
            print("\n" + baseline_note)
        if a.score:
            print("\n" + report.render_score(results))
    elif not (a.quiet and not flat):
        body = report.render_text(results, a.strict, show_clean=not a.quiet)
        if body:
            print(body)
        if baseline_note:
            print(("\n" if body else "") + baseline_note)
        if not a.quiet and skills:
            counts = {k: sum(1 for f in flat if f.severity == k)
                      for k in ("error", "warning", "info")}
            print(f"\n{len(skills)} skill(s) · {counts['error']} error · "
                  f"{counts['warning']} warning · {counts['info']} info"
                  f"  ·  `sqs.py explain <CODE>` for any of them")
        elif not a.quiet and not flat:
            print("✅ routing clean")
        if a.score:
            print("\n" + report.render_score(results))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
