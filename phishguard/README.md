# PhishGuard — Phishing Email Investigation & Detection Platform

Educational SOC Analyst project for static `.eml` analysis. It parses headers, extracts IOCs, calculates an explainable risk score, maps phishing to MITRE ATT&CK, and provides a React dashboard.

## Stack
React + Vite, FastAPI, SQLite, SQLAlchemy, JWT, Python email parser.

## Run
### Backend
```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Backend API docs: `http://127.0.0.1:8000/docs`

This version performs static analysis only and never executes attachments.
