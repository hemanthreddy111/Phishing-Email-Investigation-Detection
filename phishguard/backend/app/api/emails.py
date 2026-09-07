from fastapi import APIRouter, UploadFile, File, HTTPException
from app.services.email_parser import analyze_eml

router=APIRouter()

@router.post("/analyze")
async def analyze(file: UploadFile=File(...)):
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(400,"Only .eml files are supported")
    data=await file.read()
    if len(data)>10*1024*1024: raise HTTPException(413,"File exceeds 10 MB limit")
    return analyze_eml(data)
