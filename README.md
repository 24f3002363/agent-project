# Public HTTPS Incident Agent

FastAPI implementation for `ga5-incident-agent/v2`.

## Deploy on Render
1. Create a **public** GitHub repository and upload all files in this folder.
2. In Render, choose **New + → Blueprint** and select that repository (or create a Web Service with the settings below).
3. Set build command: `pip install -r requirements.txt`
4. Set start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. Add `OPENAI_API_KEY` as a secret environment variable. Never put the key in source control.
6. Set `MODEL_NAME` to a model enabled for your API key. Default is `gpt-4o-mini`.
7. After deploy, test `/health`, then submit the base URL such as `https://your-service.onrender.com` (no trailing path/query/fragment).

## Local run
```bash
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:OPENAI_API_KEY="YOUR_KEY"
uvicorn main:app --reload
```

Do not submit `http://localhost:8000`; the grader needs a public HTTPS URL.

## Important engineering notes
- The `sensitive` field is excluded from the model prompt and is not copied into returned state.
- SQLite is used by default for local testing. For persistent production storage on Render, attach a persistent disk or configure a managed PostgreSQL database and set `DATABASE_URL`.
- This is a starter implementation, not a verified passing submission. Exercise all receipt, retry, approval, timeout, and trace cases against the grader before spending the final Save check.
