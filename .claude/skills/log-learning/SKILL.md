---
name: log-learning
description: Record an attack attempt, finding or insight about Riley in docs/LEARNINGS.md so the team shares what works and what doesn't. Use when someone says "log this", "write this down", "record this finding", or after an attack run, a leak, a measured success rate, a dead end, or a new fix idea.
---

# Log a learning

Add an entry to `docs/LEARNINGS.md` using the template at the top of that file. Newest entries go first, directly under `## Entries`.

## Gather the facts

Take them from the conversation, the attack script's output, or `logs/my_attempts.jsonl` (each line has the request, the reply and the `turn_id`). Ask the person only for what you can't find:

- **Technique:** a short name and how it works.
- **Model(s):** exact model ids.
- **Result and rate:** worked / partly / failed, and k/n trials. If there was only one trial, say so plainly and suggest measuring more (`AGENTS.md` asks for success rates, not lucky runs).
- **Evidence:** the `turn_id`s. Never invent one: if it's missing, write "not recorded".
- **Builds on:** known prior work or "new". Novelty is 20% of the score, so be honest.
- **Fix idea:** a deterministic patch that would stop it (a rule-based input or output filter, not another model's judgement).
- **Author and date:** the person's name (from `git config user.name` if not given) and today's date.

## Write it

- Keep it short. Quote only the part of a leak that proves it (field names, one record), not whole dumps.
- If an entry for the same technique exists, update it (new rate, new `turn_id`s, date) instead of adding a duplicate.
- A failed attempt is worth logging: say why it failed.

## Never

- Write API keys, Entropy's org ID, event passwords or the contents of `.env` into the file.
- Record anything outside the fake hospital data, or any harmful content.

## After

Show the person the entry. Offer to commit it on its own (`docs: log <technique>`), but only commit if they say yes. If the finding is a confirmed leak, remind them to submit the `turn_id` through the form linked in `README.md`.
