from fastapi import APIRouter
from services.search import search
from services.cert_parser import parse_certificate_info, format_certificate_info
from typing import Optional
from pydantic import BaseModel
from bs4 import BeautifulSoup

router = APIRouter()

import os
import dotenv

# Load environment variables from .env file
dotenv.load_dotenv()

@router.get("/{cert_id}")
def get_cert(cert_id):
    """
    Retrieve certificate information by ID.
    """

    try:
        cert_id = search(os.getenv("BASE_URL") + "/?d=" + cert_id)
    except Exception as e:
        raise ValueError(f"Error fetching certificate: {e}")

    if not cert_id or not isinstance(cert_id, str):
        raise ValueError("Certificate ID is required and must be a string.")

    try:
        cert_info = parse_certificate_info(cert_id)
        formatted_cert_info = format_certificate_info(cert_info)
        return formatted_cert_info
    except Exception as e:
        raise ValueError(f"Error retrieving certificate: {e}")

class SearchRequest(BaseModel):
    search: Optional[str] = None
    value: Optional[str] = None

@router.post("/search")
def search_certs(search_request: SearchRequest):
    """
    Search for certificates based on a query.
    """
    
    if not search_request.search or not isinstance(search_request.search, str):
        raise ValueError("Search query is required and must be a string.")
    
    if not search_request.value or not isinstance(search_request.value, str):
        raise ValueError("Search value is required and must be a string.")

    search_params = ""

    try:
        match search_request.search:
            case "SHA1":
                search_params = "/?sha1="
            case "SHA256":
                search_params = "/?sha256="
            case "organisation":
                search_params = "/?O="
            case "email":
                search_params = "/?E="
            case "serialNumber":
                search_params = "/?serial="
            case "CA":
                search_params = "/?ca="

            case _:
                raise ValueError("Invalid search type. Use 'domain', 'ip', 'asn', or 'cert'.")
    except Exception as e:
        raise ValueError(f"Error processing search request: {e}")

    try:
        search_results = search(os.getenv("BASE_URL") + search_params + search_request.value)
    except Exception as e:
        raise ValueError(f"Error searching for certificates: {e}")
    
    html = BeautifulSoup(search_results, "html.parser")

    try:
        cert = html.select_one(f"tr:has(th:-soup-contains('crt.sh ID')) td a").get_text(strip=True)

        cert_info = get_cert(cert)
    except Exception as e:
        raise ValueError(f"Error finding certificate in HTML: {e}")
    
    return cert_info