# vulnerable_app -- CodeGate demo target

A small, intentionally mixed Python "app": each of the three CWEs
CodeGate tracks appears once as a vulnerable function, once as its
direct fix, plus a handful of unrelated safe functions with no security
pattern at all. The point is to show CodeGate *discriminating* -- not
just flagging everything, but telling the vulnerable version and its own
fixed version apart.

| File | Function | Shape |
|---|---|---|
| `database.py` | `get_user_by_name` | **CWE-89** -- SQL built by string concatenation |
| `database.py` | `get_user_by_id` | Safe fix -- parameterized query |
| `database.py` | `list_active_users` | Safe -- no external input reaches the query |
| `system_tasks.py` | `ping_host` | **CWE-78** -- `shell=True` with an unsanitized argument |
| `system_tasks.py` | `ping_host_safely` | Safe fix -- argv list, `shell=False` |
| `system_tasks.py` | `list_directory` | Safe -- no subprocess at all |
| `config.py` | `DATABASE_PASSWORD` | **CWE-798** -- hardcoded credential literal |
| `config.py` | `get_api_key` | Safe fix -- loaded from the environment |
| `report_utils.py` | (all) | Safe -- ordinary computation, no security-relevant pattern |
| `app.py` | (all) | Ties the above together into something that looks like an app |

## Running the scan

From the repo root, with `codegate` installed (`pip install -e .`):

```bash
codegate scan examples/vulnerable_app --no-llm
```

This uses the model and certificate already committed at
`data/model/` -- no calibration run, no API key, works on a fresh clone.
Try the other formats:

```bash
codegate scan examples/vulnerable_app --no-llm --format json
codegate scan examples/vulnerable_app --no-llm --format sarif
codegate scan examples/vulnerable_app --no-llm --format pdf --output examples/vulnerable_app/sample_report.pdf
```

`--no-llm` is used here so the demo needs no `GROQ_API_KEY`; without it,
`codegate scan` will still run everything through semgrep and the
certified gate, and additionally ask an LLM to confirm or clear whatever
the gate escalates, if `GROQ_API_KEY` is set.

A pre-generated `sample_report.pdf` is committed in this directory so
you can see what the report looks like without running anything.

## What to expect

- Semgrep (deterministic, zero LLM cost) should flag `get_user_by_name`,
  `ping_host`, and `DATABASE_PASSWORD` directly -- three static findings.
- The certified model gate additionally scores every function; whatever
  it can't certify as safe under the current calibration is escalated
  as "needs review" (or, with `GROQ_API_KEY` set, resolved by the LLM
  verifier).
- **The model backing this demo is still calibrated on a simulated
  corpus** (`corpus_version: "simulated-v2"`, `is_provisional: true` --
  visible in `codegate info` and on the PDF cover). The static findings
  above are trustworthy today; the certified miss-rate numbers are not
  yet, and will be replaced once the real corpus (Track A) lands. See
  `docs/ENGINEERING_LOG.md` section 6 for the full reasoning.
