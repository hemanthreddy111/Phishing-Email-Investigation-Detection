from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.emails import router as email_router

app=FastAPI(title="PhishGuard API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(email_router, prefix="/api/emails", tags=["emails"])

@app.get("/api/health")
def health(): return {"status":"ok","service":"phishguard"}
