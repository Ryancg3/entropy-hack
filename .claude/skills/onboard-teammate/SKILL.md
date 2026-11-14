---
name: onboard-teammate
description: Walk a new teammate through setting up this repo for the Break the Model hackathon (Nebius key, .env, packages, first chat with Riley). Use when someone says "onboard me", "set me up", "I'm new", "how do I get started", or when setup or the connection to Riley fails.
---

# Onboard a teammate

Follow `docs/ONBOARDING.md`. Do the steps for the person where you can and check each one before moving on. Keep messages short and plain: teammates may not be developers.

## Steps

1. **Python.** Run `python3 --version` (`python` on Windows). Any Python 3.9+ works.
2. **Key.** Check whether `.env` exists and has `NEBIUS_API_KEY` set to something other than the placeholder. Check by key name only: never print, echo or read back the key's value.
   - If there's no key, ask the person to run `python3 check_connection.py` in their own terminal. It asks for the key with hidden input and saves `.env`. Don't ask them to paste the key into the chat, and never type it into anything yourself.
   - In a git worktree with no `.env`, offer to link the main checkout's: `ln -s <main checkout>/.env .env`.
3. **Connection.** Run `python3 check_connection.py`. It sends one test message to the smallest model. Expect ✅ and a `turn_id`. Don't use `--all` unless asked: it spends more credit.
4. **Packages.** If `.venv` is missing, run `python3 -m venv .venv` then `.venv/bin/pip install -r requirements.txt`. Confirm with `.venv/bin/python -c "import btm; print(btm.list_models())"`.
5. **First chat.** Tell them to run `.venv/bin/python chat.py` themselves (it's interactive), and to keep the `turn_id` printed under each reply.
6. **Rules and sharing.** Point them at the ground rules in `AGENTS.md`, and at `docs/LEARNINGS.md` and `docs/TROUBLESHOOTING.md` for sharing what they find.

## When something fails

1. Look for the symptom in `docs/TROUBLESHOOTING.md` and apply the fix.
2. If it isn't there and you solve it, add an entry with the `log-issue` skill, so the next person doesn't hit it.
3. If you can't solve it, say what you tried and suggest asking an organizer.

## Don't

- Print, log or commit the Nebius key, Entropy's org ID or event passwords.
- Commit `.env`, `.venv/` or `logs/`. They're git-ignored; keep them that way.
- Send attack prompts while onboarding. The only message is the connection test.
