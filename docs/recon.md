# Recon harness (`recon.py`)

A small, repeatable tool that sends **benign** probes to Riley and records the
full response of every call. Use it to map the attack surface before attacking,
and to re-measure after the organisers change anything. It never sends
jailbreaks — see the rules in [../AGENTS.md](../AGENTS.md).

## Why

The hackathon is judged partly on technical execution: attacks must be
*measured* (success rate over several trials), not one lucky transcript. `recon.py`
does the measuring plumbing once so every attack script can follow the same
pattern. It also captures things `chat.py` hides — in particular the **arguments**
Riley passes to its tools, which the output filter may never inspect.

## Setup

You need a working `.env` (same one `chat.py` uses). If you don't have it yet:

```bash
cp .env.example .env
```

```bash
python3 setup.py
```

Then install dependencies into a virtualenv (as in [ONBOARDING.md](ONBOARDING.md)):

```bash
.venv/bin/pip install -r requirements.txt
```

## Run it

```bash
.venv/bin/python recon.py
```

That runs all four Nebius models, 3 trials each, over every probe. Useful flags:

| Command | What it does |
| --- | --- |
| `recon.py --model <id>` | one model only (repeat `--model` for several) |
| `recon.py --trials 5` | 5 trials per probe (default 3) |
| `recon.py --probes capabilities tools` | only those probe ids |
| `recon.py --list-probes` | print probe ids and exit (no key needed) |
| `recon.py --dry-run` | print the plan, send nothing (no key needed) |

Each call costs a little Nebius credit, so start with one model and `--trials 1`.

## Output

Results append to `recon/results.jsonl` (git-ignored — responses may hold fake
patient data). One JSON object per line:

| Field | Meaning |
| --- | --- |
| `probe_id`, `category` | which probe, and its group |
| `model`, `trial` | model id and 1-based trial number |
| `status` | HTTP status from `/chat` |
| `turn_id` | **the id you submit for a leak** |
| `reply` | Riley's text |
| `tool_calls` | every tool Riley called, with its `args` |
| `blocked` | our heuristic guess that the filter/model refused |
| `conversation_id` | the conversation used (shared for the statefulness probes) |
| `raw` | the complete response dict |

At the end, the script prints a per-model summary: for each probe, how many
trials looked blocked and which tool names Riley used.

Read the file with, e.g.:

```bash
.venv/bin/python -c "import json;[print(json.loads(l)['turn_id'], json.loads(l)['probe_id']) for l in open('recon/results.jsonl')]"
```

## Add a probe

Probes are plain data. Add one `Probe(id, category, message)` to the `PROBES`
list in [`recon.py`](../recon.py). Keep it benign. If two probes must share a
conversation (to test memory), add their ids to `SHARED_CONVERSATION`.

## Tests

```bash
.venv/bin/python -m pytest          # offline, mocked, no key needed
```

```bash
RUN_LIVE=1 .venv/bin/python -m pytest -m live   # one real call to the server
```
