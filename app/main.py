from __future__ import annotations

from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import FileResponse, PlainTextResponse
from starlette.routing import Route

from app.api.admin import routes as admin_routes
from app.api.analyze import routes as analyze_routes
from app.api.auth import routes as auth_routes
from app.api.reports import routes as report_routes
from app.config import BASE_DIR


async def technical_documentation(_: object):
    document_path = BASE_DIR / "docs" / "Technical Documentation.pdf"
    if not document_path.exists():
        return PlainTextResponse("Technical documentation is not available.", status_code=404)
    return FileResponse(
        document_path,
        media_type="application/pdf",
        filename="ClearURL_Technical_Documentation.pdf",
    )


app = Starlette(
    debug=True,
    routes=[
        Route("/docs/technical-documentation", technical_documentation, methods=["GET"]),
        *auth_routes,
        *analyze_routes,
        *report_routes,
        *admin_routes,
    ],
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
