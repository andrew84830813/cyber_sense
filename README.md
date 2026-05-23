# cyber-sense

An environment-triggered autonomous cybersecurity agent. It watches a process event stream, detects attack signatures without being asked, fires a LangGraph reasoning pipeline, and produces a structured threat report — start to finish, no human in the loop.

Built as the companion demo for [The Ignition Problem](./the-ignition-problem-v3.md), an article examining the difference between *execution autonomy* (the agent acts without step-by-step approval) and *initiation autonomy* (the agent starts without a human deciding to start it). This demo makes that distinction concrete in running code.

---

## The architectural claim

Most AI agents marketed as "autonomous" still require a human to pull the trigger. Someone types a prompt, clicks a button, or the agent runs on a fixed schedule. The environment never decides.

This demo is built to demonstrate the alternative: an agent that is ignited by its environment, not by a human.

```
Environment (process activity)
        │
        ▼
[Sensing layer]      sensor/monitor.py
        │            Watches events. Fires on trigger signatures.
        │            No human involved.
        │
        ▼
[Orchestration]      agent/graph.py
        │            LangGraph: 5-node pipeline
        │            trigger_received → monitor_activity →
        │            analyze_sequence → classify_threat → generate_report
        │
        ▼
[Action layer]       Structured threat report
                     Saved to output/reports/
```

Every report ends with:

```
Initiated by: environment signal (process monitor)
Human involvement: none at detection or analysis stage
```

These two lines are not decorative. They mark which autonomy class the system belongs to.

---

## Prerequisites

- Python 3.10+
- An Anthropic API key

---

## Setup

```bash
# Clone and enter the project
cd cyber-sense

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set your API key
cp .env.example .env
# Edit .env and add:  ANTHROPIC_API_KEY=sk-ant-...
```

---

## Running the demo

```bash
# All four scenarios in sequence (~45–60 seconds including LLM calls)
python demo.py

# Single scenario
python demo.py --scenario A   # PowerShell download cradle   → expects HIGH
python demo.py --scenario B   # Web shell activity            → expects HIGH
python demo.py --scenario C   # Ransomware staging            → expects CRITICAL
python demo.py --scenario N   # Normal user activity          → expects BENIGN

# Watch real process events (no LLM, shows trigger detection only)
python sensor/monitor.py --watch
```

Reports are saved to `output/reports/` after each run.

---

## The four scenarios

| Key | Name | What it models | Expected verdict |
|-----|------|----------------|-----------------|
| A | PowerShell Download Cradle | `explorer → cmd → powershell -EncodedCommand → certutil -urlcache` | HIGH |
| B | Web Shell Activity | `w3wp.exe → cmd.exe` running `whoami`, `net user`, `net group` | HIGH |
| C | Ransomware Staging | `update.exe → vssadmin delete shadows` + mass file renames to `.locked` | CRITICAL |
| N | Normal Baseline | Browser, IDE, language server, dev script | BENIGN |

See [SCENARIOS.md](./SCENARIOS.md) for the full process sequences, MITRE ATT&CK technique mappings, and a breakdown of what to look for in each report.

---

## Architecture

### Four layers

**Sensing** (`sensor/monitor.py`)
The always-on layer. Polls process events and evaluates each one against `TRIGGER_SIGNATURES` — a list of process-name and command-line patterns that indicate known attack techniques. When a signature matches, it runs a lightweight LLM triage pass (Claude Haiku) to confirm before escalating. This two-step gate — rules first, fast LLM second — keeps costs manageable without missing ambiguous cases.

**Orchestration** (`agent/graph.py`)
A five-node LangGraph `StateGraph`. Receives the trigger snapshot and full event list from the sensing layer, then runs linearly: log the trigger → format the process tree → analyze with a ReAct agent → classify with structured JSON → generate the final report. Two LLM calls (Claude Sonnet) are made per scenario: analysis and classification.

**Agent** (`agent/agent.py`)
A `create_react_agent` instance with four tools: `format_process_tree`, `identify_attack_patterns`, `lookup_mitre_technique`, and `get_similar_threats`. Uses `MemorySaver` so all scenarios in a single demo run share session context — the agent can reference earlier detections in its reasoning.

**Memory** (`memory/store.py`)
Two-tier persistence. Short-term: `MemorySaver` in the agent checkpointer, scoped to the current session. Long-term: ChromaDB vector store at `output/chroma_db/`, plus a human-readable `output/threat_history.json`. The `get_similar_threats` tool lets the agent do semantic similarity search over all past detections across runs.

### What the pipeline state looks like

```python
class ThreatState(TypedDict):
    scenario_name:    str
    session_id:       str
    trigger:          Dict       # the process snapshot that fired the sensor
    process_events:   List[Dict] # full event stream for the monitoring window
    process_sequence: str        # formatted process tree (set by monitor_activity)
    analysis:         str        # narrative threat analysis (set by analyze_sequence)
    classification:   Dict       # structured verdict JSON (set by classify_threat)
    report:           str        # final formatted report (set by generate_report)
```

Each node reads from the state and returns a partial update. The state accumulates context as it moves through the pipeline.

### Simulated vs. real monitoring

The demo runs simulated process events so it works on any machine without elevated permissions. The sensing layer is architecturally identical in both modes: the same `is_trigger()` logic and the same callback interface are used regardless of whether events come from `psutil` or a pre-built list.

The simulation hook is clearly marked in `sensor/monitor.py`:

```python
snapshot = {
    ...
    # SIMULATION HOOK: in demo mode, a pre-built cmdline is injected here
    # instead of reading from the live process. Everything downstream is identical.
    "cmdline": proc.info["cmdline"] or [],
    ...
}
```

To switch to real monitoring: `python sensor/monitor.py --watch`

---

## Interactive exploration

`cyber_sense_playground.ipynb` provides a section-by-section walkthrough:

1. **Setup** — load scenarios, verify API key
2. **Browse scenarios** — inspect and edit event sequences
3. **Sensor dry run** — watch trigger detection without LLM calls
4. **Step through the pipeline** — run each LangGraph node individually and inspect intermediate state
5. **Full end-to-end run** — invoke `run_scenario()` and capture the report
6. **Custom scenario** — define your own process sequence and run it through the pipeline
7. **Layer inspection** — import and test each of the four layers independently

---

## Extending the demo

### Add a trigger signature

Edit `sensor/monitor.py`:

```python
TRIGGER_SIGNATURES = [
    # existing signatures...
    {"parent": "outlook.exe", "process": "mshta.exe"},  # Outlook → MSHTA execution
]
```

Each signature is a dict with any combination of `process`, `parent`, and `cmdline_contains` keys. All specified keys must match for the trigger to fire.

### Add a new scenario

1. Add a function to `simulation/malicious.py` (or `simulation/normal.py`) that returns `(events_list, scenario_name)`
2. Add it to `SCENARIOS` in `demo.py`
3. If the scenario uses a new technique, add it to `TRIGGER_SIGNATURES` in `sensor/monitor.py`

The event dict schema:

```python
{
    "timestamp":   "HH:MM:SS",
    "pid":         int,
    "name":        "process.exe",
    "parent_pid":  int | None,
    "parent_name": "parent.exe" | None,
    "cmdline":     "full command line string",
    "action":      "process_start" | "network_connection" | "file_rename",
    "detail":      "optional detail string",  # used for non-process_start actions
}
```

### Add a MITRE technique

Edit `agent/tools.py` → `lookup_mitre_technique()`, and `agent/prompts.py` → `SYSTEM_PROMPT` (the quick reference block).

---

## Project layout

```
cyber-sense/
├── demo.py                     # entry point — runs all four scenarios
├── requirements.txt
├── the-ignition-problem-v3.md  # the article this demo accompanies
├── SCENARIOS.md                # detailed scenario reference
│
├── sensor/
│   └── monitor.py              # sensing layer: trigger signatures, triage, real + simulated modes
│
├── simulation/
│   ├── malicious.py            # scenarios A, B, C — attack event sequences
│   └── normal.py               # scenario N — benign baseline
│
├── agent/
│   ├── graph.py                # LangGraph pipeline (5 nodes + ThreatState)
│   ├── agent.py                # ReAct agent with MemorySaver
│   ├── tools.py                # four agent tools + format helpers
│   └── prompts.py              # all LLM prompts as named constants
│
├── memory/
│   └── store.py                # ChromaDB vector store + JSON backup
│
└── output/
    ├── reports/                # generated threat reports
    ├── chroma_db/              # vector store (persisted across runs)
    └── threat_history.json     # human-readable detection log
```

---

## LLM usage and cost

Each malicious scenario makes two Sonnet calls: one for `analyze_sequence` (via the ReAct agent) and one for `classify_threat`. The triage pass uses Haiku. The normal scenario skips triage and makes two Sonnet calls directly.

The system prompt is marked `cache_control: ephemeral` in both the agent and the classifier. On subsequent tool-call turns within a 5-minute window, the prompt is served from Anthropic's prompt cache at ~10% of the standard input token cost.

Running all four scenarios costs roughly $0.02–0.05 depending on analysis length.

---

## Article

[The Ignition Problem](./the-ignition-problem-v3.md) — the piece this demo was built to accompany. It defines execution autonomy vs. initiation autonomy, examines where today's most celebrated agent systems actually sit, and argues that the ignition mechanism is an infrastructure property, not an agent property.
