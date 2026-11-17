# Classification guidance (no code changes needed)

Copy `config/classification_rules.example.json` to
`config/classification_rules.json` on the R-Vision server. Edit only
the JSON file to tune model guidance. This file is **optional**; when
absent, the parser behaves as before.

Category names under `categories` must exactly match the names in
`categories.json`. For each category, optional keys are:

- `description`: free-text criteria for choosing this category
- `positive_indicators`: signals supporting the category
- `negative_indicators`: signals arguing against it
- `examples`: illustrative classification examples

`general_rules` is a list of overall instructions. Values are sent
to the LLM as guidance along with the existing reference dictionaries.
They are not deterministic keyword matches. Negations, hypothetical
phrases and incident context still matter.

For the Credential Manager example with
`rundll32.exe keymgr.dll,KRShowKeyMgr`, the sample guidance prefers
`Событие безопасности / Подозрение на инцидент ИБ` when malware is not
confirmed. This is **not a guaranteed outcome**: the model may still
make mistakes. Existing output validation only checks that selected
categories and types exist in your reference dictionaries.

After changing the file, simply run the parser again. No code edits,
pip installations or service restarts are needed for the CLI.
