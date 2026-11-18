# SOAR performance tuning (CentOS 7, Python 3.6)

The parser can compact repeated update blocks before sending incident text to Ollama.
Only update blocks whose event descriptions match after removal of their
leading event timestamps are combined. Distinct bodies are kept. A repeated
description is annotated with its occurrence count. Disable with
`preprocessing.deduplicate_updates=false` if exact event timestamps are
required for downstream extraction.

Copy relevant settings into your existing `config/settings.json`:

```json
{
  "base_url": "http://10.201.198.47:11434",
  "model": "qwen9B:latest",
  "timeout": 90,
  "max_retries": 0,
  "max_duration": 300,
  "num_predict": 512,
  "preprocessing": {"deduplicate_updates": true}
}
```

`timeout` limits each Ollama HTTP request; `max_duration` caps total
Ollama attempts and, in the Linux SOAR entrypoint, enforces a hard
wall-clock limit for the preprocessing and request stage. If exceeded,
the CLI exits with code 1, writes an error to stderr, and does not print
a success JSON. The R-Vision SSH exec timeout should exceed this deadline,
including connection and startup overhead. Lower `timeout` to e.g.
60-90 seconds for faster failure if required. `num_predict` limits
generation length; raise it if JSON responses are truncated.

System instructions are already in English; translating incident evidence
is not necessary. Performance depends on the model, server hardware, prompt
size and output token count. The settings are starting points, not measured
latency guarantees.
