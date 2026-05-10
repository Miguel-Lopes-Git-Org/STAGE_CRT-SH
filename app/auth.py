from hmac import compare_digest
from typing import Optional

from fastapi import HTTPException, Security
from fastapi.security import api_key
from starlette import status
from dotenv import load_dotenv
import os

load_dotenv()

api_key_header = api_key.APIKeyHeader(name="X-API-KEY", auto_error=False)
api_key_query = api_key.APIKeyQuery(name="api_key", auto_error=False)


def _expected_api_key() -> str:
    expected_key = os.getenv("API_KEY")
    if not expected_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API key is not configured on the server",
        )
    return expected_key


def _check_api_key(key: Optional[str]) -> str:
    expected_key = _expected_api_key()
    if not key or not compare_digest(key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized - API Key is wrong",
        )
    return key


async def validate_api_key(key: Optional[str] = Security(api_key_header)):
    return _check_api_key(key)


async def validate_docs_api_key(
    header_key: Optional[str] = Security(api_key_header),
    query_key: Optional[str] = Security(api_key_query),
):
    return _check_api_key(header_key or query_key)
