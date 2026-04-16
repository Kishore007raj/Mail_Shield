from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Float
from app.db.database import Base


class AnalyzedEmail(Base):
    """Stores each analyzed email along with its forensic results."""

    __tablename__ = "analyzed_emails"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    subject = Column(String(500), nullable=True)
    sender = Column(String(320), nullable=True)
    receiver = Column(String(320), nullable=True)
    body = Column(Text, nullable=True)
    raw_headers = Column(Text, nullable=True)
    risk_score = Column(Integer, nullable=False, default=0)
    classification = Column(String(20), nullable=False, default="Safe")
    reasons = Column(JSON, nullable=False, default=list)
    details = Column(JSON, nullable=False, default=dict)
    analyzed_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return (
            f"<AnalyzedEmail(id={self.id}, subject='{self.subject}', "
            f"classification='{self.classification}', risk_score={self.risk_score})>"
        )
