from fastapi import APIRouter
from services.search import search
from services.cert_parser import parse_certificate_info, format_certificate_info

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