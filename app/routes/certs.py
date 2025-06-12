from fastapi import APIRouter, HTTPException, Path
from services.search import search
from services.cert_parser import parse_certificate_info, format_certificate_info
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from bs4 import BeautifulSoup

from services.cert_id import get_cert_id
from services.cert_transparency import get_certificat_transparency
from services.revocation import get_revocation_info
from services.cert_fingerprint import get_certificate_fingerprints
from services.cert_parser import parse_certificate_info
from services.get_all_cert import get_all_certificates
from services.get_ca import get_all_ca_info

import os
import dotenv

# Load environment variables from .env file
dotenv.load_dotenv()

router = APIRouter(
    tags=["Certificates"],
    responses={
        404: {"description": "Certificate not found"},
        422: {"description": "Invalid certificate ID or search parameters"},
        500: {"description": "Internal server error"}
    }
)

# Response Models for better API documentation
class CertificateDetailsResponse(BaseModel):
    """Complete certificate information response model"""
    Certificate: Dict[str, Any] = Field(
        description="Detailed certificate information including subject, issuer, extensions, etc.",
        example={
            "Version": "3 (0x2)",
            "Serial Number": "04:a1:b2:c3:d4:e5:f6:78:90:ab:cd:ef:12:34:56:78",
            "Signature Algorithm": "sha256WithRSAEncryption",
            "Issuer": {
                "C": "US",
                "O": "DigiCert Inc",
                "CN": "DigiCert SHA2 Secure Server CA"
            },
            "Validity": {
                "Not Before": "Dec 15 00:00:00 2024 GMT",
                "Not After": "Mar 15 23:59:59 2025 GMT"
            },
            "Subject": {
                "CN": "example.com"
            },
            "X509v3 extensions": {
                "X509v3 Subject Alternative Name": [
                    "DNS:example.com",
                    "DNS:www.example.com"
                ],
                "X509v3 Key Usage": {
                    "critical": True,
                    "usages": ["Digital Signature", "Key Encipherment"]
                }
            }
        }
    )

class CertificateSearchResponse(BaseModel):
    """Response model for certificate search operations"""
    crt_sh_id: Optional[str] = Field(None, description="Certificate ID from crt.sh", example="123456789")
    certificate_transparency: Optional[List[Dict[str, Any]]] = Field(
        None, 
        description="Certificate transparency log entries",
        example=[
            {
                "timestamp": "2024-12-15 14:30:42 UTC",
                "entry_number": "123456789",
                "log_operator": "Google",
                "log_url": "https://ct.googleapis.com/logs/us1/argon2024h2"
            }
        ]
    )
    revocation: Optional[List[Dict[str, Any]]] = Field(
        None, 
        description="Certificate revocation information",
        example=[
            {
                "mechanism": "OCSP",
                "provider": "DigiCert",
                "status": "Good",
                "revocation_date": None,
                "last_observed_in_crl": None,
                "last_checked": "2024-12-20 10:30:15"
            }
        ]
    )
    certificate_fingerprint: Optional[Dict[str, str]] = Field(
        None, 
        description="SHA-1 and SHA-256 fingerprints",
        example={
            "sha1": "A1B2C3D4E5F6789012345678901234567890ABCD",
            "sha256": "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
        }
    )
    certificate_info: Optional[Dict[str, Any]] = Field(None, description="Parsed certificate information")
    certificates: Optional[List[Dict[str, Any]]] = Field(
        None, 
        description="List of certificates for organization/email searches",
        example=[
            {
                "crt_id": "123456789",
                "common_name": "example.com",
                "issuer_name": "DigiCert Inc",
                "not_before": "2024-12-15",
                "not_after": "2025-03-15"
            },
            {
                "crt_id": "987654321",
                "common_name": "api.example.com",
                "issuer_name": "Let's Encrypt",
                "not_before": "2024-11-01",
                "not_after": "2025-02-01"
            }
        ]
    )

class CertificateAuthorityResponse(BaseModel):
    """Response model for Certificate Authority information"""
    ca_id: Optional[str] = Field(None, description="Certificate Authority ID", example="16418")
    Subject: Optional[Dict[str, str]] = Field(
        None, 
        description="CA subject information",
        example={
            "C": "US",
            "O": "DigiCert Inc",
            "OU": "www.digicert.com",
            "CN": "DigiCert SHA2 Secure Server CA"
        }
    )
    certificates: Optional[List[Dict[str, Any]]] = Field(
        None, 
        description="Certificates issued by this CA",
        example=[
            {
                "crt_id": "123456789",
                "common_name": "example.com",
                "not_before": "2024-12-15",
                "not_after": "2025-03-15"
            }
        ]
    )
    Population: Optional[Dict[str, Dict[str, str]]] = Field(
        None, 
        description="Certificate population statistics",
        example={
            "Certificates": {
                "Unexpired": "1,234,567",
                "Expired": "2,345,678",
                "Total": "3,580,245"
            }
        }
    )
    Trust: Optional[Dict[str, Dict[str, str]]] = Field(
        None, 
        description="Trust store information",
        example={
            "Server Authentication": {
                "Microsoft": "Yes",
                "Mozilla": "Yes",
                "Apple": "Yes",
                "Google": "Yes"
            }
        }
    )

@router.get(
    "/{certificate_id}",
    response_model=CertificateDetailsResponse,
    summary="Get certificate details",
    description="Retrieve comprehensive certificate information by crt.sh ID"
)
def get_certificate_details(
    certificate_id: str = Path(..., description="Certificate ID from crt.sh", example="123456789")
) -> CertificateDetailsResponse:
    """
    Retrieve comprehensive certificate information by crt.sh certificate ID.
    
    This endpoint fetches detailed certificate information from crt.sh including:
    - Certificate subject and issuer details
    - Validity periods and serial numbers
    - Public key information and algorithms
    - X.509v3 extensions (Key Usage, SAN, etc.)
    - Certificate policies and constraints
    - Digital signature information
    
    The certificate data is parsed from the raw certificate format and structured
    into a comprehensive JSON response for easy consumption.
    
    Args:
        certificate_id: The crt.sh certificate ID to retrieve details for
        
    Returns:
        CertificateDetailsResponse: Complete parsed certificate information
        
    Raises:
        HTTPException: 400 if certificate ID is invalid
        HTTPException: 404 if certificate not found
        HTTPException: 500 if parsing fails
        
    Example:
        GET /certs/123456789
        Returns detailed certificate information including subject, issuer, extensions, etc.
    """
    if not certificate_id or not isinstance(certificate_id, str):
        raise HTTPException(
            status_code=400, 
            detail="Certificate ID is required and must be a valid string"
        )

    try:
        # Fetch certificate data from crt.sh
        certificate_search_url = f"{os.getenv('BASE_URL')}/?id={certificate_id}"
        raw_certificate_html = search(certificate_search_url)
        
        if not raw_certificate_html:
            raise HTTPException(
                status_code=404,
                detail=f"Certificate with ID '{certificate_id}' not found"
            )
        
        # Parse certificate information from HTML
        parsed_certificate_info = parse_certificate_info(raw_certificate_html)
        formatted_certificate_data = format_certificate_info(parsed_certificate_info)
        
        return CertificateDetailsResponse(**formatted_certificate_data)
        
    except HTTPException:
        raise
    except Exception as parsing_error:
        raise HTTPException(
            status_code=500, 
            detail=f"Error retrieving certificate details: {str(parsing_error)}"
        )

class CertificateSearchRequest(BaseModel):
    """Request model for certificate search operations"""
    search: str = Field(
        ..., 
        description="Search type: SHA1, SHA256, organisation, email, serialNumber, or CA",
        example="SHA256"
    )
    value: str = Field(
        ..., 
        description="Search value corresponding to the search type",
        example="1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
    )
    
    class Config:
        schema_extra = {
            "examples": {
                "sha256_search": {
                    "summary": "Search by SHA-256 fingerprint",
                    "value": {
                        "search": "SHA256",
                        "value": "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
                    }
                },
                "organization_search": {
                    "summary": "Search by organization",
                    "value": {
                        "search": "organisation",
                        "value": "Google Inc"
                    }
                },
                "ca_search": {
                    "summary": "Search by Certificate Authority",
                    "value": {
                        "search": "CA",
                        "value": "16418"
                    }
                }
            }
        }

@router.post(
    "/search",
    response_model=CertificateSearchResponse,
    summary="Search for certificates",
    description="Search for certificates using various criteria (hash, organization, email, etc.)"
)
def search_certificates(
    search_request: CertificateSearchRequest
) -> CertificateSearchResponse:
    """
    Search for certificates using various search criteria.
    
    This endpoint supports multiple search types to find certificates in the crt.sh database:
    
    **Hash-based searches:**
    - SHA1: Search by SHA-1 fingerprint (40 hex characters)
    - SHA256: Search by SHA-256 fingerprint (64 hex characters)
    
    **Organization/Entity searches:**
    - organisation: Search by organization name in certificate subject
    - email: Search by email address in certificate subject
    - serialNumber: Search by certificate serial number
    
    **Certificate Authority searches:**
    - CA: Search by Certificate Authority ID to get CA details and issued certificates
    
    Different search types return different response structures:
    - Hash searches: Return detailed certificate info including transparency logs and revocation status
    - Organization/email/serial searches: Return list of matching certificates
    - CA searches: Return comprehensive CA information including issued certificates and trust data
    
    Args:
        search_request: Contains search type and value
        
    Returns:
        CertificateSearchResponse: Search results in appropriate format based on search type
        
    Raises:
        HTTPException: 400 if search parameters are invalid
        HTTPException: 404 if no results found
        HTTPException: 500 if search operation fails
        
    Examples:
        POST /certs/search
        Body: {"search": "SHA256", "value": "A60C802959EC14CD5989043660905903D6436D0119C39715D71F316B3EF3A631"}
        Returns detailed certificate information
        
        POST /certs/search  
        Body: {"search": "organisation", "value": "Google Inc"}
        Returns list of certificates issued to Google Inc
    """
    search_type = search_request.search
    search_value = search_request.value
    
    # Validate search parameters
    if not search_type or not isinstance(search_type, str):
        raise HTTPException(
            status_code=400, 
            detail="Search type is required and must be a valid string"
        )
    
    if not search_value or not isinstance(search_value, str):
        raise HTTPException(
            status_code=400, 
            detail="Search value is required and must be a valid string"
        )

    # Map search types to crt.sh URL parameters
    search_parameter_mapping = {
        "SHA1": "/?sha1=",
        "SHA256": "/?sha256=", 
        "organisation": "/?O=",
        "email": "/?E=",
        "serialNumber": "/?serial=",
        "CA": "/?ca="
    }
    
    # Validate search type
    if search_type not in search_parameter_mapping:
        available_types = ", ".join(search_parameter_mapping.keys())
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid search type '{search_type}'. Available types: {available_types}"
        )

    try:
        # Build search URL and execute search
        search_url_parameter = search_parameter_mapping[search_type]
        complete_search_url = f"{os.getenv('BASE_URL')}{search_url_parameter}{search_value}"
        raw_search_results = search(complete_search_url)
        
        if not raw_search_results:
            raise HTTPException(
                status_code=404,
                detail=f"No results found for {search_type} search with value '{search_value}'"
            )
        
    except HTTPException:
        raise
    except Exception as search_error:
        raise HTTPException(
            status_code=500, 
            detail=f"Error executing search: {str(search_error)}"
        )

    # Process search results based on search type
    try:
        search_response_data = {}
        
        if search_type in ["SHA1", "SHA256"]:
            # Hash-based searches return detailed certificate information
            search_response_data = {
                "crt_sh_id": get_cert_id(raw_search_results),
                "certificate_transparency": get_certificat_transparency(raw_search_results),
                "revocation": get_revocation_info(raw_search_results),
                "certificate_fingerprint": get_certificate_fingerprints(raw_search_results),
                "certificate_info": parse_certificate_info(raw_search_results)
            }
            
        elif search_type in ["organisation", "email", "serialNumber"]:
            # Organization/email/serial searches return certificate lists
            certificate_list = get_all_certificates(
                raw_search_results, 
                subdomains_only=False, 
                remove_duplicates=False
            )
            search_response_data = {"certificates": certificate_list}
            
        elif search_type == "CA":
            # CA searches return comprehensive CA information
            ca_information = get_all_ca_info(raw_search_results)
            search_response_data = ca_information
            
    except Exception as processing_error:
        raise HTTPException(
            status_code=500, 
            detail=f"Error processing search results: {str(processing_error)}"
        )
    
    return CertificateSearchResponse(**search_response_data)