from fastapi import APIRouter, HTTPException, Request

from database.database import (
    get_all_investigation_summaries,
    get_investigation
)

import json


router = APIRouter(
    prefix="/api/investigations",
    tags=["Investigations"]
)


@router.get("")
def list_investigations(request: Request):

    try:

        principal = getattr(request.state, "principal", None)
        investigations = get_all_investigation_summaries(
            principal.tenant_id if principal else None
        )

        return {
            "success": True,
            "count": len(investigations),
            "investigations": investigations
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch investigations: {str(error)}"
        )


@router.get("/{investigation_id}")
def get_single_investigation(
    investigation_id: str,
    request: Request,
):

    try:

        principal = getattr(request.state, "principal", None)
        investigation = get_investigation(
            investigation_id,
            principal.tenant_id if principal else None,
        )

        if investigation is None:

            raise HTTPException(
                status_code=404,
                detail="Investigation not found."
            )

        try:

            investigation["analysis"] = json.loads(
                investigation.get(
                    "analysis_json",
                    "{}"
                )
            )

        except Exception:

            investigation["analysis"] = {}

        investigation.pop(
            "analysis_json",
            None
        )

        return {
            "success": True,
            "investigation": investigation
        }

    except HTTPException:

        raise

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch investigation: {str(error)}"
        )
