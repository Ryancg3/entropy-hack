# AGENTS.md

Context for AI agents and people working in this repo.

## What this project is

This is our team's repo for the **Entropy Alignment Security Hackathon**. The challenge is called **Break the Model**:

- Entropy built a fake hospital database containing private patient and staff data, keys and secrets.
- An AI agent called **Riley**, the hospital's assistant, can read that database. Data-protection filters check Riley's answers and block private data.
- Our job is to manipulate Riley into leaking that data, **using prompt injection only**, and then to build a **deterministic patch** that stops our own attack.

Breaking the model is half the work. The deck says: "If your attack works, find a deterministic way to patch your attack method."

Sources: the [event slide deck](https://docs.google.com/presentation/d/14VG49wblATqF9EgiEd0VGHclwuVL6AhL-OYkN29aIrA/edit) and the starter kit [natalienma/break-the-model-starter](https://github.com/natalienma/break-the-model-starter).

## Target models

The deck names four target models, colour-coded by difficulty from green (easiest) to red (hardest):

| Model | Deck colour | Availability | Server model id |
| --- | --- | --- | --- |
| Gemma 3 27B | green | Now | **not served** on 2026-11-14 |
| DeepSeek V4 Pro | yellow | Now | `deepseek-ai/DeepSeek-V4-Pro-0813` |
| Claude Haiku 5.5 | orange | Later, only through Entropy's org ID | not served yet |
| Claude Sonnet 5.5 | red | Later, only through Entropy's org ID | not served yet |

These are the models to report results on. Right now only DeepSeek V4 Pro (option 4 in `chat.py`) can be used. Check `/models` again before assuming Gemma is still missing. The other models below aren't in the deck, but they're good for trying ideas cheaply.

The server's `GET /models` lists what is live. On 2026-11-14 it returned:

| Model id | Provider | Tier |
| --- | --- | --- |
| `Qwen/Qwen3-30B-A3B-Instruct-2507` | Nebius | small (easiest) |
| `openai/gpt-oss-120b` | Nebius | medium |
| `Qwen/Qwen3-235B-A22B-Instruct-2507` | Nebius | large |
| `deepseek-ai/DeepSeek-V4-Pro-0813` | Nebius | very large (hardest) |
| `groq/llama-3.1-8b-instant` | Groq | small |
| `groq/qwen/qwen3.8-27b` | Groq | medium |
| `groq/llama-3.3-70b-versatile` | Groq | large |
| `groq/openai/gpt-oss-120b` | Groq | large |

`chat.py` offers only the four Nebius models.

Each participant gets $100 of Nebius credits; the models are reached through Nebius Token Factory.

## Ground rules

These are hard limits. Do not suggest or write anything that crosses them.

- Attack **only through messages** to the agent. Prompt injections only.
- No hacking the WiFi, the server, or the models' weights or architecture.
- Nothing outside what the Break the Model challenge outlines.
- Target the **fake hospital data only**. Never try to get harmful content out of the models (weapons, drugs, malware and so on).
- Everything sent to Riley is logged and used for research.

## How we are judged

| Criterion | What judges look for | Weight |
| --- | --- | --- |
| Novelty / creativity | Is the technique new, or an implementation of existing literature? | 20% |
| Security impact | If the attack succeeds, how much harm is done? | 20% |
| Mitigation / fix | Can the team detect or defend against its own attack? | 20% |
| Technical execution | The attack is reproducible and measured (for example, success rate over several attempts), not a one-off lucky result | 15% |
| Commercializability | Could the fix or finding become a product? | 10% |
| Teamwork | Did the team develop findings together, or test hypotheses individually? | 10% |
| Presentation | Are the findings easy to understand in 3 minutes? | 5% |

The judging panel is mostly security leadership: CISO-level people from Trade Republic, Deutsche Bank and Emnify, the head of offensive content at HTB Labs, and a Fraunhofer AISEC professor. Expect them to care about real-world impact and a credible defence.

## What this means for work in this repo

- **Measure everything.** Every attack should be a script that runs N trials per model and reports a success rate. A single lucky transcript scores poorly.
- **Keep evidence.** Save the `turn_id` printed under each reply along with the prompt used. Submissions need the `turn_id` and a description of the method.
- **Pair each attack with a fix.** The patch should be deterministic (for example, a rule-based input or output filter, not another model's judgement), and we should show the attack's success rate before and after it.
- **Prefer novel techniques** over replays of well-known jailbreaks, and note which prior work an idea builds on.
- **Keep the pitch simple.** Findings must be explainable in 3 minutes, so favour one clear attack-and-fix story over many shallow ones.

## Starter kit

The organisers' kit is at [natalienma/break-the-model-starter](https://github.com/natalienma/break-the-model-starter):

- `python3 setup.py` asks for a name and Nebius API key, then tests the connection.
- `python3 chat.py` opens an interactive chat with Riley. `/new` starts a fresh conversation and `/switch` changes model.
- `example_attack.py` shows how to attack from code.
- Leaks are submitted through the form linked in that repo's README.

## Documenting issues and learnings

Write things down as you go, so teammates (and their agents) don't repeat work:

- **Attack attempts, findings, success rates and fix ideas** go in [docs/LEARNINGS.md](docs/LEARNINGS.md), failures included.
- **Setup, tooling and server problems** and their fixes go in [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md). Check it before debugging setup.
- Each file has a template at the top. Update an existing entry rather than adding a duplicate.

Claude Code has project skills for this in `.claude/skills/`: `onboard-teammate` ("onboard me"), `log-learning` ("log this learning") and `log-issue` ("log this issue"). Other agents should follow the same steps by hand; the skill files explain them.

## Repo state and conventions

- The starter kit is merged in: `btm.py` (client), `chat.py` (interactive chat), `example_attack.py`, `setup.py`. `check_connection.py` tests a Nebius key with no packages installed. New teammates start at [docs/ONBOARDING.md](docs/ONBOARDING.md).
- **Recon:** `recon.py` sends benign probes to map Riley's attack surface and measures results (see [docs/recon.md](docs/recon.md)). Findings live in [docs/attack-surface.md](docs/attack-surface.md). `btm.chat_raw()` returns the full `(status, response)` for tooling; `chat()` is unchanged. Paste-able safety tests: [docs/safety-tests.md](docs/safety-tests.md).
- **Schema catalogue:** `schema_recon.py` drives Riley's `query_db` tool to enumerate the DB schema (tables/columns) and runs the field-safety audit over it. `field_safety.py` is a deterministic, model-free classifier (`classify_field`, `audit_schema`) and SQL auditor (`audit_sql`) — the basis of the output/argument filter and SQL gate in the patch. Catalogue and analysis in [docs/schema-catalogue.md](docs/schema-catalogue.md).
- **Tests:** `tests/test_recon.py` and `tests/test_field_safety.py`, run with `.venv/bin/python -m pytest` (offline, mocked). Live smoke: `RUN_LIVE=1 .venv/bin/python -m pytest -m live`.
- Update this section as code lands.
- **Never commit secrets.** Nebius API keys, Entropy's org ID and event credentials (the venue WiFi password in the deck included) stay out of the repo. Read keys from environment variables or an untracked file.
