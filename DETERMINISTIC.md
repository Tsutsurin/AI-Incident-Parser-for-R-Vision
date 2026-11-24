# Deterministic parser

Both CLI entry points now use the rule-based parser. Existing settings.json and reference files remain usable. New configuration files fall back to their tracked .example.json versions. Copy them to the corresponding .json names to customize.

- patterns: field labels, inline extraction patterns, update and explanation boundaries.
- parser_classification: prioritized regex rules, separate from legacy LLM classification_rules.
- normalization: corporate domains and short host names.
- known_local_accounts: editable local/service account names; explicit corporate domain wins.
- network_zones: configure actual controlled CIDRs and domain suffixes. Leave complete_inventory false unless the inventory is exhaustive. Unknown zone defaults to anomalous activity.
- exceptions: legacy domain-controller exception is supported; new rules use values and condition {"match":"any","patterns":["regex"]}.

LLM verification is disabled unless settings.json contains "llm_verification": {"enabled":true,"timeout":3}. It is advisory only, with a maximum five-second Linux alarm and no retries. Results always come from the deterministic parser. A client timeout does not guarantee immediate cancellation on Ollama.

Run tests with python3 -m unittest discover -s tests -p test_deterministic.py. Test on staging before deploying. The initial rule set is not exhaustive; unknown scenarios fall back to suspicion.

SOAR command remains python3 -m app.main_soar --incident "text" or --stdin. Only JSON is written to stdout.
