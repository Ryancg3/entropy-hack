# Onboarding

Welcome to the team. This gets you from zero to chatting with Riley in about five minutes.

If you use Claude Code, open this repo and say **"onboard me"**. It walks you through the same steps and fixes problems as they come up.

## 1. Get the repo

```bash
git clone git@github.com:Ryancg3/entropy-hack.git && cd entropy-hack
```

## 2. Get a Nebius key

**Nebius Token Factory → API keys → Create**. Copy it. You get $100 of credits, and each message to Riley costs a little.

## 3. Check your key works

```bash
python3 check_connection.py
```

It asks for your name and key, saves them to `.env` (git-ignored, never committed) and sends Riley one test message. You should see ✅ and a `turn_id`. Nothing needs installing for this step.

If it fails, look in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## 4. Install the packages for the chat client

```bash
python3 -m venv .venv
```

```bash
.venv/bin/pip install -r requirements.txt
```

On Windows, use `python` instead of `python3` and `.venv\Scripts\pip` instead of `.venv/bin/pip`.

## 5. Talk to Riley

```bash
.venv/bin/python chat.py
```

Pick a model by number. `/new` starts a fresh conversation, `/switch` changes model. Every reply prints a `turn_id`: keep it, because submissions need it. Your attempts are also saved to `logs/my_attempts.jsonl` (git-ignored).

## 6. Read the ground rules

[AGENTS.md](../AGENTS.md) has the challenge, the hard rules and how we're judged. In short: attack only through messages, target the fake hospital data only, and measure everything.

## 7. Write down what you learn

We share findings so nobody repeats a dead end:

- **Attack ideas and results** (what worked, what didn't, success rates, `turn_id`s) go in [LEARNINGS.md](LEARNINGS.md).
- **Setup or tooling problems** and their fixes go in [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

In Claude Code, say **"log this learning"** or **"log this issue"** and it writes the entry for you. Without Claude Code, copy the template at the top of each file.

Never put API keys, Entropy's org ID or event passwords in any of these files.
