"""
MailTrace AI — Threat Intelligence API
"""

from fastapi import APIRouter, HTTPException, Request

from database.database import (
    initialize_threat_intelligence_table,
    get_threat_intelligence,
    get_threat_intelligence_source_status,
)
from services.threat_intelligence import ThreatIntelligenceEngine
from services.threat_intelligence.sync_service import sync_threat_intelligence_feeds


router = APIRouter(
    prefix="/api/threat-intelligence",
    tags=["Threat Intelligence"],
)


try:
    initialize_threat_intelligence_table()
except Exception:
    pass


@router.get("/status")
def threat_intelligence_status():

    return {
        "success": True,
        "service": "threat-intelligence",
        "providers":
            ThreatIntelligenceEngine.provider_status(),
        "feed_freshness": get_threat_intelligence_source_status(),
    }


@router.post("/sync")
def threat_intelligence_sync(
    request: Request,
    days: int = 1,
):

    if days < 1:
        days = 1

    if days > 7:
        days = 7

    principal = getattr(getattr(request, "state", None), "principal", None)
    return sync_threat_intelligence_feeds(
        days=days,
        synced_by=getattr(principal, "subject_id", None),
    )


@router.get("/indicators")
def threat_intelligence_indicators(
    limit: int = 100,
):

    limit = max(
        1,
        min(int(limit), 500),
    )

    indicators = get_threat_intelligence(
        limit=limit,
    )

    return {
        "success": True,
        "count": len(indicators),
        "indicators": indicators,
    }
