# CentOS 7 / Python 3.6.8 deployment

The SOAR runtime uses **only the Python 3.6 standard library**. No pip packages
are required to execute the parser.

Copy the repository (at minimum `app/` and `config/`) to the server.
Ensure `config/settings.json` points to the reachable Ollama host.

From the project root:

```bash
python3 -m app.main_soar --help
printf '%s' 'Test incident' | python3 -m app.main_soar --stdin
python3 -m app.main_soar --incident 'Test incident'
```

On success, stdout contains one JSON object. Errors go to stderr, exit code 1.
The CLI does not create input or output files. It uses the existing
`/api/generate` Ollama endpoint. Ensure outbound access to Ollama from
the R-Vision host; internet access is not required.

For development tests only, install `requirements-dev.txt` on a machine
with an appropriate Python environment and run `python -m pytest`.
Do not replace the system Python interpreter.

**Security:** The internal Ollama URL bypasses environment HTTP proxies.
Use trusted TLS or a protected network for sensitive incident data.
