
# CodeSentry AI — Hackathon MVP

CodeSentry AI is a defensive code-review web app for indie developers and small teams. It combines local, rule-based checks with optional Gemini model review.

## MVP features

- Upload Python/JavaScript/TypeScript/Java/Go/PHP/Ruby/SQL/shell source files or a ZIP.
- Scan for several common security patterns locally.
- Optionally request a structured JSON review from Gemini.
- Review findings with file, line, evidence, severity, and remediation.
- Download the report as JSON.
- The app analyzes source as text and does **not** execute uploaded code.

## Run locally

Use Python 3.10+.

```bash
python -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate

pip install -r requirements.txt
streamlit run app.py
```

Then open the local URL Streamlit prints.

## Configure Gemini (optional)

1. Obtain API access and a key from the Google AI developer platform or the hackathon organizers.
2. Copy `.env.example` to `.env` and fill in `GEMINI_API_KEY` and `GEMINI_MODEL`, or enter the key in the app sidebar.
3. Install the requirements and restart the app.
4. Confirm the exact model ID and access path supplied by the hackathon. If `gemini-4-argon` is unavailable to your account, use the model ID your organizers provide.

The app uses the official `google-genai` Python SDK and requests JSON-shaped output. Model availability, billing, quotas, and API behavior depend on your account and the provider's current policies.

## Demo

1. Upload `sample_vulnerable.py`.
2. Click **Analyze code** with AI off to show local rule findings.
3. If Gemini access is available, enter the API key, turn on AI analysis, and run the review again.
4. Open a finding and explain the evidence and recommendation.
5. Download the JSON report.

## Limitations / honest claims

- This MVP does not execute code, apply patches, run tests, or prove that a fix is safe.
- Static rules are intentionally simple and can produce false positives or miss issues.
- AI findings need human review; model-generated line numbers and explanations can be incorrect.
- Keep API keys secret. Do not upload private repositories, credentials, or sensitive data without authorization.
- For production, add authentication, rate limiting, stronger archive limits, isolated patch/test execution, a test suite, and a broader security benchmark.

## Suggested next milestone

Add a controlled patch-preview workflow: let the model propose a unified diff, validate the diff applies to the selected file, show the change for human approval, and run tests only inside an isolated container with no secrets and restricted network access.
