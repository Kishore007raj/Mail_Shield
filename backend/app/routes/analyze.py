import logging
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from app.db.database import get_db
from app.db.models import AnalyzedEmail
from app.services.parser import parse_raw_email, parse_eml_file
from app.services.rule_engine import analyze_rules
from app.services.ml_model import predict
from app.services.url_analyzer import analyze_urls
from app.services.header_analyzer import analyze_headers
from app.services.risk_engine import calculate_risk

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["analysis"])


class EmailInput(BaseModel):
    """Request body for raw email text analysis."""
    raw_email: str


class AnalysisResponse(BaseModel):
    """Structured analysis response."""
    id: int
    risk_score: int
    classification: str
    reasons: list[str]
    details: dict
    subject: Optional[str] = None
    sender: Optional[str] = None
    receiver: Optional[str] = None
    analyzed_at: str


def _run_analysis(parsed_email, db: Session) -> dict:
    """Core analysis pipeline shared by both endpoints."""

    rule_flags = analyze_rules(parsed_email.subject, parsed_email.body)

    ml_prediction = predict(f"{parsed_email.subject} {parsed_email.body}")

    url_findings = analyze_urls(parsed_email.urls)

    header_issues = analyze_headers(
        sender=parsed_email.sender,
        reply_to=parsed_email.reply_to,
        return_path=parsed_email.return_path,
        received_chain=parsed_email.received_chain,
        headers=parsed_email.headers,
        authentication_results=parsed_email.authentication_results,
        dkim_signature=parsed_email.dkim_signature,
        message_id=parsed_email.message_id,
        x_mailer=parsed_email.x_mailer,
    )

    risk_result = calculate_risk(
        rule_flags=rule_flags,
        url_findings=url_findings,
        header_issues=header_issues,
        ml_prediction=ml_prediction,
    )

    db_record = AnalyzedEmail(
        subject=parsed_email.subject or None,
        sender=parsed_email.sender or None,
        receiver=parsed_email.receiver or None,
        body=parsed_email.body[:10000] if parsed_email.body else None,
        raw_headers=parsed_email.raw_headers[:5000] if parsed_email.raw_headers else None,
        risk_score=risk_result["risk_score"],
        classification=risk_result["classification"],
        reasons=risk_result["reasons"],
        details=risk_result["details"],
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    return {
        "id": db_record.id,
        "risk_score": risk_result["risk_score"],
        "classification": risk_result["classification"],
        "reasons": risk_result["reasons"],
        "details": risk_result["details"],
        "subject": parsed_email.subject,
        "sender": parsed_email.sender,
        "receiver": parsed_email.receiver,
        "analyzed_at": db_record.analyzed_at.isoformat(),
    }


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_raw_email(payload: EmailInput, db: Session = Depends(get_db)):
    """Analyze a raw email text for phishing indicators."""
    logger.info("Received raw email for analysis")

    if not payload.raw_email or not payload.raw_email.strip():
        raise HTTPException(status_code=400, detail="Email content cannot be empty")

    try:
        parsed = parse_raw_email(payload.raw_email)
        result = _run_analysis(parsed, db)
        logger.info(f"Analysis complete: ID={result['id']}, Classification={result['classification']}")
        return result

    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/analyze/upload", response_model=AnalysisResponse)
async def analyze_eml_upload(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Analyze an uploaded .eml file for phishing indicators."""
    logger.info(f"Received file upload: {file.filename}")

    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported")

    try:
        file_bytes = await file.read()
        if not file_bytes:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        parsed = parse_eml_file(file_bytes)
        result = _run_analysis(parsed, db)
        logger.info(f"Upload analysis complete: ID={result['id']}, Classification={result['classification']}")
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload analysis failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.get("/history")
async def get_analysis_history(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """Retrieve analysis history with pagination."""
    records = (
        db.query(AnalyzedEmail)
        .order_by(AnalyzedEmail.analyzed_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return [
        {
            "id": r.id,
            "subject": r.subject,
            "sender": r.sender,
            "risk_score": r.risk_score,
            "classification": r.classification,
            "analyzed_at": r.analyzed_at.isoformat(),
        }
        for r in records
    ]


@router.get("/history/{analysis_id}")
async def get_analysis_detail(analysis_id: int, db: Session = Depends(get_db)):
    """Retrieve detailed analysis result by ID."""
    record = db.query(AnalyzedEmail).filter(AnalyzedEmail.id == analysis_id).first()

    if not record:
        raise HTTPException(status_code=404, detail=f"Analysis record {analysis_id} not found")

    return {
        "id": record.id,
        "subject": record.subject,
        "sender": record.sender,
        "receiver": record.receiver,
        "risk_score": record.risk_score,
        "classification": record.classification,
        "reasons": record.reasons,
        "details": record.details,
        "analyzed_at": record.analyzed_at.isoformat(),
    }
