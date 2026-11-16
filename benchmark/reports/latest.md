# SecureMCP benchmark

Experiment `5c062279-82a0-48b5-98c5-f886c8494ea3`

SQLite isolated snapshots, in-process Streamable HTTP, live OPA

| Mode | Scenarios | UER | ASR | Legitimate completion | p95 scenario latency (ms) |
|---|---:|---:|---:|---:|---:|
| direct | 450 | 0.5 | 0.7 | 1.0 | 194.6 |
| prompt_only | 450 | 0.3662 | 0.48889 | 1.0 | 161.99 |
| protected | 450 | 0.0 | 0.0 | 1.0 | 1775.8 |

Command: `python -m securemcp.lab --selection all --repeats 3`

The prompt-only mode models a scripted refusal for explicit attacks. These results measure deterministic behavior and observed mutations.
