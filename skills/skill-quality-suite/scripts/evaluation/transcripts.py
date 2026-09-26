#!/usr/bin/env python3
"""A skill's own loads, cut out of the user's history and written down for a judge.

The counts in `history` see what fails loudly: a call that errors, a stop by the person.
A step the agent skipped fails in silence - nothing errors when a verification is left
out and the work is reported done - and only a reader holding the skill's steps beside
what the agent did can see it. That reader is a model, so the judging is paid. This
module is the free half: it finds the loads, cuts each one out, masks secrets, and
writes them where the judge will read them. Nothing is sent anywhere.

A load runs from the `Skill` call (or a typed `/command`) to the person's next message,
which is kept too: a correction right after "done" is the plainest sign a step was
skipped. The skill text that loaded is kept as well, once per distinct version, because
a session from before an edit has to be judged against the skill it actually ran.

The rubric and the bar for turning a judged failure into an edit live in
references/judging-sessions.md; both are adapted from Warp's skill-doctor (MIT).
"""
import glob
import hashlib
import json
import os
import re

from evaluation import history

# Per-entry caps, so one pasted document or one long tool output cannot crowd out the
# rest of the load. Taken from skill-doctor's collector (1500 for prose, 500 for tool
# output); the middle of a load is never dropped, unlike there, because the middle of a
# load is where a skill's steps are followed or skipped.
MAX_TEXT = 1500
MAX_CALL = 300
MAX_RESULT = 500
# skill-doctor samples twelve sessions by default; a judge reads every one of them, so the
# number is the reading budget rather than a statistic.
DEFAULT_LOADS = 12
BASE_DIR_RE = re.compile(r"\ABase directory for this skill:[^\n]*\n+")
# Claude Code appends the call's arguments to the skill text it injects. They are the
# request the agent handed the skill, not the skill: left in, one unchanged SKILL.md came
# out of a real history as four "versions", one per set of arguments.
ARGS_RE = re.compile(r"\n+ARGUMENTS: (.*)\Z", re.S)


def _cut(text, limit):
    text = text.strip()
    return text if len(text) <= limit else text[:limit] + f" [... {len(text) - limit} chars cut]"


def _norm(text):
    return " ".join(text.split())


def _loads_in(path, names):
    """[{"prompt", "ts", "entries", "body", "reaction", "interrupted"}] for one transcript."""
    out, cur, prompt = [], None, ""
    try:
        f = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return out
    with f:
        for line in f:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not isinstance(rec, dict) or rec.get("isSidechain"):
                continue
            content = (rec.get("message") or {}).get("content")
            if rec.get("type") == "user":
                text = history._user_text(content)
                if text is None:
                    if cur is not None and isinstance(content, list):
                        for b in content:
                            if not (isinstance(b, dict) and b.get("type") == "tool_result"):
                                continue
                            result = history.redact(history._result_text(b))
                            if result.startswith("Launching skill:"):
                                continue               # the load's own receipt
                            if history.INTERRUPT_RE.search(result):
                                cur["interrupted"] = True
                                cur["entries"].append(("stop", "stopped by the person"))
                            elif b.get("is_error"):
                                cur["entries"].append(("error", _cut(result, MAX_RESULT)))
                            else:
                                cur["entries"].append(("result", _cut(result, MAX_RESULT)))
                    continue
                if rec.get("isMeta"):
                    if cur is not None and cur["body"] is None and BASE_DIR_RE.match(text):
                        body = BASE_DIR_RE.sub("", text, count=1)
                        m = ARGS_RE.search(body)
                        if m:
                            cur["args"] = _cut(history.redact(m.group(1)), MAX_TEXT)
                            body = body[:m.start()]
                        cur["body"] = body
                    continue
                if rec.get("isCompactSummary"):
                    continue
                if history.INTERRUPT_RE.search(text):
                    if cur is not None:
                        cur["interrupted"] = True
                        cur["entries"].append(("stop", "stopped by the person"))
                    continue
                typed = None
                if text.lstrip().startswith("<"):
                    m = history.COMMAND_TAG_RE.search(text)
                    if not m:
                        continue                       # a reminder, not the person
                    typed = m.group(1).split(":")[-1]
                    args = history.COMMAND_ARGS_RE.search(text)
                    text = args.group(1) if args else ""
                if cur is not None:
                    cur["reaction"] = _cut(history.redact(text), MAX_TEXT) or "(a command)"
                    cur = None
                prompt = _cut(history.redact(text), MAX_TEXT)
                if typed in names:
                    cur = {"prompt": prompt, "ts": rec.get("timestamp") or "", "entries": [],
                           "body": None, "reaction": None, "interrupted": False}
                    out.append(cur)
            elif rec.get("type") == "assistant" and isinstance(content, list):
                for b in content:
                    if not isinstance(b, dict):
                        continue
                    if b.get("type") == "tool_use" and b.get("name") == "Skill":
                        loaded = ((b.get("input") or {}).get("skill") or "").split(":")[-1]
                        cur = None                     # another load ends this one
                        if loaded in names:
                            cur = {"prompt": prompt, "ts": rec.get("timestamp") or "",
                                   "entries": [], "body": None, "reaction": None,
                                   "interrupted": False}
                            out.append(cur)
                    elif cur is None:
                        continue
                    elif b.get("type") == "text" and b.get("text", "").strip():
                        cur["entries"].append(("agent", _cut(b["text"], MAX_TEXT)))
                    elif b.get("type") == "tool_use":
                        tool, inp = b.get("name"), b.get("input") or {}
                        key = history.redact(history._call_key(tool, inp))
                        cur["entries"].append(("call", f"{tool}: {_cut(key, MAX_CALL)}"))
    return out


def collect(skill, history_dir=None, limit=DEFAULT_LOADS):
    """The latest `limit` loads of `skill`, newest first, with the versions that loaded.

    A session that edited the skill is building it, and a judge would score the author's
    experiments as the skill's failures: those loads are counted and left out, the same
    exclusion `ran_unloaded` makes.
    """
    names = {skill.folder, (skill.name or skill.folder).split(":")[-1]}
    building = history._worked_on(history_dir)
    loads, skipped = [], 0
    root = history_dir or history.default_dir()
    for path in sorted(glob.glob(os.path.join(root, "*", "*.jsonl"))):
        found = _loads_in(path, names)
        if found and names & building.get(path, set()):
            skipped += len(found)
            continue
        for x in found:
            x["session"] = os.path.splitext(os.path.basename(path))[0]
            x["project"] = os.path.basename(os.path.dirname(path))
            loads.append(x)
    total = len(loads)
    loads.sort(key=lambda x: (x["ts"], x["session"]), reverse=True)
    loads = loads[:limit]
    current = _norm(skill.body)
    versions = {}
    for x in loads:
        if x["body"] is None:
            x["version"] = None
            continue
        sha = hashlib.sha256(_norm(x["body"]).encode("utf-8")).hexdigest()[:12]
        v = versions.setdefault(sha, {"label": f"v{len(versions) + 1}", "body": x["body"],
                                      "same_as_current": _norm(x["body"]) == current
                                      if current else False, "loads": 0})
        v["loads"] += 1
        x["version"] = v["label"]
    return {"skill": skill.folder, "skill_md": skill.md_path, "found": total,
            "skipped_building": skipped, "loads": loads, "versions": versions}


def _render(x, n, of, skill, versions):
    v = next((v for v in versions.values() if v["label"] == x["version"]), None)
    if v is None:
        loaded = "not in the transcript - judge against the current SKILL.md, and say so"
    elif v["same_as_current"]:
        loaded = f"{v['label']}, the same as the current SKILL.md"
    else:
        loaded = f"{v['label']} (loaded-{v['label']}.md), not the current SKILL.md"
    lines = [f"# {skill} - load {n} of {of}", "",
             f"session {x['session'][:8]} · project {x['project']} · {x['ts'] or 'no time'}",
             f"skill text that loaded: {loaded}", "", "## The request", "",
             x["prompt"] or "(none typed before the load)", ""]
    if x.get("args"):
        lines += ["What the agent handed the skill:", "", x["args"], ""]
    lines += ["## The work after the load", ""]
    lines += [f"- **{kind}** {' '.join(text.split())}" for kind, text in x["entries"]] or [
        "- nothing: the turn ended at the load"]
    lines += ["", "## The person's next message", "",
              x["reaction"] or "(none: the session ended, or another skill took over)", ""]
    return "\n".join(lines)


def write(result, out_dir):
    """Write the loads and versions under `out_dir/<skill>/`; return the files and chars."""
    target = os.path.join(out_dir, result["skill"])
    os.makedirs(target, exist_ok=True)
    files, chars = [], 0
    for v in result["versions"].values():
        p = os.path.join(target, f"loaded-{v['label']}.md")
        with open(p, "w", encoding="utf-8") as f:
            f.write(v["body"])
        files.append(p)
        chars += len(v["body"])
    of = len(result["loads"])
    index = []
    for n, x in enumerate(result["loads"], 1):
        text = _render(x, n, of, result["skill"], result["versions"])
        name = f"{n:02}-{(x['ts'] or 'undated')[:10]}-{x['session'][:8]}.md"
        with open(os.path.join(target, name), "w", encoding="utf-8") as f:
            f.write(text)
        files.append(os.path.join(target, name))
        chars += len(text)
        index.append({"file": name, "session": x["session"], "project": x["project"],
                      "time": x["ts"], "version": x["version"],
                      "stopped": x["interrupted"], "next_message": bool(x["reaction"])})
    with open(os.path.join(target, "index.json"), "w", encoding="utf-8") as f:
        json.dump({"skill": result["skill"], "skill_md": result["skill_md"],
                   "loads_found": result["found"], "loads_written": of,
                   "skipped_building": result["skipped_building"],
                   "versions": {v["label"]: {"sha": k, "same_as_current": v["same_as_current"],
                                             "loads": v["loads"]}
                                for k, v in result["versions"].items()},
                   "loads": index}, f, ensure_ascii=False, indent=2)
    return {"dir": target, "files": len(files), "chars": chars}
