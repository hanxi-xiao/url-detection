from app.module2.preprocessing import PreprocessingError, preprocess_submission


def test_preprocess_adds_https_when_missing() -> None:
    result = preprocess_submission({"url": "example.com/login"})
    assert result.normalized_url == "https://example.com/login"
    assert result.scheme == "https"
    assert result.domain == "example.com"
    assert result.warnings


def test_preprocess_rejects_invalid_scheme() -> None:
    try:
        preprocess_submission({"url": "ftp://example.com/file"})
    except PreprocessingError as error:
        assert error.code == "UNSUPPORTED_SCHEME"
    else:
        raise AssertionError("Expected PreprocessingError")
