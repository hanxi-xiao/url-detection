import asyncio

from app.main import technical_documentation


def test_technical_documentation_pdf_is_available() -> None:
    response = asyncio.run(technical_documentation(None))

    assert response.status_code == 200
    assert response.media_type == "application/pdf"
    assert response.path.stat().st_size > 1_000
