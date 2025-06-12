from fastapi import APIRouter, HTTPException, Query, Path
from fastapi.responses import JSONResponse
from services.search import search
from services.cert_parser import parse_certificate_info, format_certificate_info
from bs4 import BeautifulSoup
import operator
from datetime import datetime
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import asyncio

import os
import dotenv

from services.get_all_cert import get_all_certificates

# Load environment variables from .env file
dotenv.load_dotenv()

router = APIRouter(
    tags=["Subdomains"],
    responses={
        404: {"description": "Domain not found"},
        422: {"description": "Invalid input parameters"},
        500: {"description": "Internal server error"}
    }
)

# Response Models for better API documentation
class SubdomainCertificate(BaseModel):
    """Model representing a subdomain certificate"""
    crt_id: Optional[str] = Field(None, description="Certificate ID from crt.sh")
    logged_at: Optional[str] = Field(None, description="Date when certificate was logged")
    not_before: Optional[str] = Field(None, description="Certificate validity start date")
    not_after: Optional[str] = Field(None, description="Certificate validity end date")
    common_name: Optional[str] = Field(None, description="Certificate common name")
    matching_identities: Optional[str] = Field(None, description="Matching SANs/identities")
    issuer_name: Optional[str] = Field(None, description="Certificate issuer name")

class SubdomainsResponse(BaseModel):
    """Response model for subdomains endpoint"""
    subdomains: List[SubdomainCertificate] = Field(description="List of subdomain certificates")

class CertificateIdResponse(BaseModel):
    """Response model for certificate ID"""
    crt_sh_id: str = Field(description="Certificate ID from crt.sh")

class LatestCertificateResponse(BaseModel):
    """Response model for latest certificate"""
    last_cert: Dict[str, Any] = Field(
        description="Latest certificate information",
        example={
            "domain": "api.example.com",
            "id": "123456789",
            "logged_at": "2024-12-15",
            "not_before": "2024-12-15",
            "not_after": "2025-03-15"
        }
    )

class OrderedCertificatesResponse(BaseModel):
    """Response model for ordered certificates"""
    certs: Dict[str, Dict[str, Any]] = Field(
        description="Ordered certificates by domain",
        example={
            "www.example.com": {
                "id": "987654321",
                "logged_at": "2024-12-01",
                "not_before": "2024-12-01",
                "not_after": "2025-03-01"
            },
            "api.example.com": {
                "id": "123456789",
                "logged_at": "2024-11-15",
                "not_before": "2024-11-15",
                "not_after": "2025-02-15"
            },
            "mail.example.com": {
                "id": "456789123",
                "logged_at": "2024-10-01",
                "not_before": "2024-10-01",
                "not_after": "2025-01-01"
            }
        }
    )

class AnomaliesResponse(BaseModel):
    """Response model for certificate anomalies"""
    self_signed: Dict[str, Dict[str, Any]] = Field(
        description="Self-signed certificates",
        example={
            "test.example.com": {
                "id": "111222333",
                "logged_at": "2024-08-15",
                "not_before": "2024-08-15",
                "not_after": "2024-11-15",
                "issuer": "Self-Signed CA"
            },
            "dev.example.com": {
                "id": "444555666",
                "logged_at": "2024-09-01",
                "not_before": "2024-09-01",
                "not_after": "2024-12-01",
                "issuer": "Internal CA"
            }
        }
    )
    expired: Dict[str, Dict[str, Any]] = Field(
        description="Expired certificates",
        example={
            "old.example.com": {
                "id": "777888999",
                "logged_at": "2023-06-01",
                "not_before": "2023-06-01",
                "not_after": "2023-09-01"
            },
            "legacy.example.com": {
                "id": "000111222",
                "logged_at": "2023-03-15",
                "not_before": "2023-03-15",
                "not_after": "2023-06-15"
            }
        }
    )

class AggregatedDomainsResponse(BaseModel):
    """Response model for aggregated domains"""
    aggregated_domains: List[Dict[str, Any]] = Field(
        description="Aggregated domain information",
        example=[
            {
                "domain": "example.com",
                "subdomains": [
                    {
                        "crt_id": "123456789",
                        "common_name": "www.example.com",
                        "not_before": "2024-12-01",
                        "not_after": "2025-03-01"
                    },
                    {
                        "crt_id": "987654321",
                        "common_name": "api.example.com",
                        "not_before": "2024-11-15",
                        "not_after": "2025-02-15"
                    }
                ]
            },
            {
                "domain": "test.org",
                "subdomains": [
                    {
                        "crt_id": "456789123",
                        "common_name": "mail.test.org",
                        "not_before": "2024-10-01",
                        "not_after": "2025-01-01"
                    }
                ]
            }
        ]
    )

def remove_duplicate_entries(certificate_list: List) -> List:
    """
    Remove duplicate entries from a certificate list.
    
    Args:
        certificate_list: List of certificates that may contain duplicates
        
    Returns:
        List with unique entries only
    """
    return list(set(certificate_list))

@router.get(
    "/{domain_name}/subdomains",
    response_model=SubdomainsResponse,
    summary="Get domain subdomains",
    description="Retrieve all subdomain certificates for a specific domain from crt.sh database"
)
async def get_domain_subdomains(
    domain_name: str = Path(..., description="Target domain name to search for subdomains", example="example.com")
) -> SubdomainsResponse:
    """
    Retrieve a comprehensive list of subdomains and their certificates for a given domain.
    
    This endpoint searches the crt.sh certificate transparency database for all certificates
    issued to subdomains of the specified domain. It filters results to show only subdomains
    and removes duplicate entries for cleaner output.
    
    Args:
        domain_name: The target domain to search for (e.g., "example.com")
        
    Returns:
        SubdomainsResponse: Contains list of subdomain certificates with their details
        
    Raises:
        HTTPException: 400 if domain name is invalid
        HTTPException: 500 if search service fails
        
    Example:
        GET /domains/example.com/subdomains
        Returns certificates for api.example.com, www.example.com, etc.
    """
    if not domain_name or not isinstance(domain_name, str):
        raise HTTPException(status_code=400, detail="Domain name is required and must be a valid string")
    
    try:
        # Search crt.sh for certificates matching the domain
        search_url = f"{os.getenv('BASE_URL')}/?q={domain_name}"
        certificate_html_data = search(search_url)
        
        # Extract subdomain certificates from HTML response
        subdomain_certificates = get_all_certificates(
            certificate_html_data, 
            remove_duplicates=True, 
            subdomains_only=True
        )
        
        return SubdomainsResponse(subdomains=subdomain_certificates)
        
    except Exception as search_error:
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to retrieve subdomains for domain '{domain_name}': {str(search_error)}"
        )

@router.get(
    "/{domain_name}/subdomains/{subdomain_name}/certs",
    response_model=CertificateIdResponse,
    summary="Get subdomain certificate ID",
    description="Retrieve the certificate ID for a specific subdomain"
)
def get_subdomain_certificate_id(
    domain_name: str = Path(..., description="Parent domain name", example="example.com"),
    subdomain_name: str = Path(..., description="Specific subdomain name", example="api.example.com")
) -> CertificateIdResponse:
    """
    Retrieve the certificate ID for a specific subdomain from crt.sh database.
    
    This endpoint searches for certificates associated with a specific subdomain
    and returns the crt.sh certificate ID for further detailed queries.
    
    Args:
        domain_name: The parent domain name
        subdomain_name: The specific subdomain to find certificate for
        
    Returns:
        CertificateIdResponse: Contains the crt.sh certificate ID
        
    Raises:
        HTTPException: 400 if parameters are invalid
        HTTPException: 404 if subdomain certificate not found
        HTTPException: 500 if search fails
    """
    # Validate input parameters
    if not domain_name or not isinstance(domain_name, str):
        raise HTTPException(status_code=400, detail="Domain name is required and must be a valid string")
    
    if not subdomain_name or not isinstance(subdomain_name, str):
        raise HTTPException(status_code=400, detail="Subdomain name is required and must be a valid string")

    try:
        # Search for domain certificates
        search_url = f"{os.getenv('BASE_URL')}/?q={domain_name}"
        certificate_html_data = search(search_url)
        
        # Parse HTML to find specific subdomain certificate
        html_parser = BeautifulSoup(certificate_html_data, "html.parser")
        
        # Find certificate ID for the specific subdomain
        certificate_row = html_parser.select_one(f"tr:has(td:-soup-contains('{subdomain_name}')) td:nth-child(1) a")
        
        if not certificate_row:
            raise HTTPException(
                status_code=404, 
                detail=f"No certificate found for subdomain '{subdomain_name}' under domain '{domain_name}'"
            )
            
        certificate_id = certificate_row.get_text(strip=True)
        return CertificateIdResponse(crt_sh_id=certificate_id)
        
    except HTTPException:
        raise
    except Exception as processing_error:
        raise HTTPException(
            status_code=500, 
            detail=f"Error processing subdomain certificate search: {str(processing_error)}"
        )

@router.get(
    "/{domain_name}/subdomains/{subdomain_name}/latest",
    response_model=LatestCertificateResponse,
    summary="Get latest subdomain certificate",
    description="Retrieve the most recent certificate for a specific subdomain"
)
def get_latest_subdomain_certificate(
    domain_name: str = Path(..., description="Parent domain name", example="example.com"),
    subdomain_name: str = Path(..., description="Specific subdomain name", example="api.example.com")
) -> LatestCertificateResponse:
    """
    Retrieve the most recent certificate issued for a specific subdomain.
    
    This endpoint finds all certificates for a subdomain and returns the one
    with the latest 'not_before' date, indicating the most recently issued certificate.
    
    Args:
        domain_name: The parent domain name
        subdomain_name: The specific subdomain to find latest certificate for
        
    Returns:
        LatestCertificateResponse: Contains the latest certificate details
        
    Raises:
        HTTPException: 400 if parameters are invalid  
        HTTPException: 404 if no certificates found for subdomain
        HTTPException: 500 if processing fails
    """
    # Validate input parameters
    if not domain_name or not isinstance(domain_name, str):
        raise HTTPException(status_code=400, detail="Domain name is required and must be a valid string")
    
    if not subdomain_name or not isinstance(subdomain_name, str):
        raise HTTPException(status_code=400, detail="Subdomain name is required and must be a valid string")

    try:
        # Search for domain certificates
        search_url = f"{os.getenv('BASE_URL')}/?q={domain_name}"
        certificate_html_data = search(search_url)
        
        # Parse HTML to extract certificate data
        html_parser = BeautifulSoup(certificate_html_data, "html.parser")
        certificate_rows = html_parser.select("tr:has(td:nth-child(6)):not(:first-child)")

        # Filter certificates for the specific subdomain
        matching_subdomain_certificates = []
        for certificate_row in certificate_rows:
            table_cells = certificate_row.find_all('td')
            if len(table_cells) >= 6:
                certificate_domain_name = table_cells[4].get_text(strip=True)
                if certificate_domain_name == subdomain_name:
                    certificate_details = {
                        "domain": certificate_domain_name,
                        "id": table_cells[0].get_text(strip=True),
                        "logged_at": table_cells[1].get_text(strip=True),
                        "not_before": table_cells[2].get_text(strip=True),
                        "not_after": table_cells[3].get_text(strip=True)
                    }
                    matching_subdomain_certificates.append(certificate_details)

        if not matching_subdomain_certificates:
            raise HTTPException(
                status_code=404, 
                detail=f"No certificates found for subdomain '{subdomain_name}'"
            )

        # Find the latest certificate based on not_before date
        latest_certificate = max(
            matching_subdomain_certificates, 
            key=lambda cert: datetime.strptime(cert['not_before'], '%Y-%m-%d')
        )

        return LatestCertificateResponse(last_cert=latest_certificate)
        
    except HTTPException:
        raise
    except Exception as processing_error:
        raise HTTPException(
            status_code=500, 
            detail=f"Error finding latest certificate for subdomain: {str(processing_error)}"
        )

class OrderedCertificatesRequest(BaseModel):
    """Request model for ordered certificates"""
    revert: Optional[bool] = Field(False, description="Whether to reverse the sort order (newest first)")

@router.post(
    "/{domain_name}/subdomains/ordered",
    response_model=OrderedCertificatesResponse,
    summary="Get ordered subdomain certificates",
    description="Retrieve certificates for all subdomains, ordered by issue date"
)
def get_ordered_subdomain_certificates(
    domain_name: str = Path(..., description="Domain name to search", example="example.com"),
    request_body: OrderedCertificatesRequest = None
) -> OrderedCertificatesResponse:
    """
    Retrieve certificates for all subdomains of a domain, ordered by issue date.
    
    This endpoint returns all certificates for subdomains under the specified domain,
    sorted by their 'not_before' date. The sort order can be controlled via the request body.
    
    Args:
        domain_name: The domain to search for subdomain certificates
        request_body: Optional request body to control sort order
        
    Returns:
        OrderedCertificatesResponse: Dictionary of certificates ordered by date
        
    Raises:
        HTTPException: 400 if domain name is invalid
        HTTPException: 500 if processing fails
    """
    should_reverse_order = request_body.revert if request_body else False
    
    if not domain_name or not isinstance(domain_name, str):
        raise HTTPException(status_code=400, detail="Domain name is required and must be a valid string")

    try:
        # Search for domain certificates
        search_url = f"{os.getenv('BASE_URL')}/?q={domain_name}"
        certificate_html_data = search(search_url)
        
        # Parse HTML to extract certificate data
        html_parser = BeautifulSoup(certificate_html_data, "html.parser")
        certificate_rows = html_parser.select("tr:has(td:nth-child(6)):not(:first-child)")

        # Extract certificate information for each subdomain
        certificates_by_domain = {
            certificate_row.find_all('td')[4].get_text(strip=True): {
                "id": certificate_row.find_all('td')[0].get_text(strip=True),
                "logged_at": certificate_row.find_all('td')[1].get_text(strip=True),
                "not_before": certificate_row.find_all('td')[2].get_text(strip=True),
                "not_after": certificate_row.find_all('td')[3].get_text(strip=True)
            }
            for certificate_row in certificate_rows 
            if len(certificate_row.find_all('td')) >= 6
        }

        # Sort certificates by not_before date (preserves order in Python 3.7+)
        sorted_certificates = dict(sorted(
            certificates_by_domain.items(), 
            key=lambda item: datetime.strptime(item[1]['not_before'], '%Y-%m-%d'), 
            reverse=should_reverse_order
        ))

        return OrderedCertificatesResponse(certs=sorted_certificates)
        
    except Exception as processing_error:
        raise HTTPException(
            status_code=500, 
            detail=f"Error retrieving ordered certificates: {str(processing_error)}"
        )

@router.get(
    "/{domain_name}/anomalies",
    response_model=AnomaliesResponse,
    summary="Detect certificate anomalies",
    description="Identify potentially suspicious certificates (self-signed, expired, etc.)"
)
def detect_certificate_anomalies(
    domain_name: str = Path(..., description="Domain name to analyze", example="example.com")
) -> AnomaliesResponse:
    """
    Detect and categorize certificate anomalies for a domain.
    
    This endpoint analyzes all certificates for a domain and identifies potential
    security concerns such as:
    - Self-signed or non-standard CA certificates
    - Expired certificates
    - Other suspicious patterns
    
    Args:
        domain_name: The domain to analyze for certificate anomalies
        
    Returns:
        AnomaliesResponse: Categorized anomalies found in domain certificates
        
    Raises:
        HTTPException: 400 if domain name is invalid
        HTTPException: 500 if analysis fails
    """
    if not domain_name or not isinstance(domain_name, str):
        raise HTTPException(status_code=400, detail="Domain name is required and must be a valid string")

    try:
        # Search for domain certificates
        search_url = f"{os.getenv('BASE_URL')}/?q={domain_name}"
        certificate_html_data = search(search_url)
        
        # Parse HTML to extract certificate data
        html_parser = BeautifulSoup(certificate_html_data, "html.parser")
        certificate_rows = html_parser.select("tr:has(td:nth-child(6)):not(:first-child)")

        suspicious_self_signed_certificates = {}
        expired_certificates = {}

        # Analyze each certificate for anomalies
        for certificate_row in certificate_rows:
            table_cells = certificate_row.find_all('td')
            if len(table_cells) >= 6:
                certificate_id = table_cells[0].get_text(strip=True)
                certificate_domain_name = table_cells[4].get_text(strip=True)
                certificate_expiry_date = table_cells[3].get_text(strip=True)
                
                # Check if certificate is expired
                try:
                    expiry_datetime = datetime.strptime(certificate_expiry_date, '%Y-%m-%d')
                    current_datetime = datetime.now()
                    
                    if expiry_datetime < current_datetime:
                        expired_certificates[certificate_domain_name] = {
                            "id": certificate_id,
                            "logged_at": table_cells[1].get_text(strip=True),
                            "not_before": table_cells[2].get_text(strip=True),
                            "not_after": certificate_expiry_date
                        }
                except ValueError:
                    # Skip certificates with invalid date format
                    continue
                
                # Analyze certificate issuer for suspicious patterns
                try:
                    issuer_link_elements = certificate_row.find_all("a")
                    if len(issuer_link_elements) > 1:
                        issuer_organization_data = issuer_link_elements[1].get_text(strip=True)
                        
                        # Extract organization from issuer string (O=Organization)
                        if "O=" in issuer_organization_data:
                            certificate_authority = issuer_organization_data.split("O=")[1].split(",")[0].replace('"', '')
                            
                            # Define list of certificate auto signed
                            suspicious_ca_list = ["Let's Encrypt"]  # This should be customized based on requirements

                            # Check if the certificate authority is flagged
                            if certificate_authority in suspicious_ca_list:
                                suspicious_self_signed_certificates[certificate_domain_name] = {
                                    "id": certificate_id,
                                    "logged_at": table_cells[1].get_text(strip=True),
                                    "not_before": table_cells[2].get_text(strip=True),
                                    "not_after": certificate_expiry_date,
                                    "issuer": certificate_authority
                                }
                                
                except (IndexError, AttributeError):
                    # Skip certificates where issuer cannot be extracted
                    continue

        return AnomaliesResponse(
            self_signed=suspicious_self_signed_certificates,
            expired=expired_certificates
        )
        
    except Exception as analysis_error:
        raise HTTPException(
            status_code=500, 
            detail=f"Error analyzing certificate anomalies: {str(analysis_error)}"
        )

class DomainAggregationRequest(BaseModel):
    """Request model for domain aggregation"""
    domains: List[str] = Field(..., description="List of domains to aggregate", example=["example.com", "test.org"])

@router.post(
    "/aggregate",
    response_model=AggregatedDomainsResponse,
    summary="Aggregate multiple domains",
    description="Batch process multiple domains to get subdomain information with rate limiting"
)
async def aggregate_multiple_domains(
    request_body: DomainAggregationRequest
) -> AggregatedDomainsResponse:
    """
    Aggregate subdomain information for multiple domains in batches.
    
    This endpoint processes multiple domains in parallel batches to efficiently
    gather subdomain certificate information. It includes rate limiting to respect
    crt.sh service limits and prevent overwhelming their servers.
    
    Features:
    - Batch processing (5 domains per batch)
    - Rate limiting (60 second delay between batches)
    - Parallel processing within batches
    - Comprehensive error handling
    
    Args:
        request_body: Contains list of domains to process
        
    Returns:
        AggregatedDomainsResponse: Aggregated subdomain data for all domains
        
    Raises:
        HTTPException: 400 if domain list is invalid
        HTTPException: 500 if processing fails
    """
    domain_list = request_body.domains
    
    # Validate input
    if not isinstance(domain_list, list) or not all(isinstance(domain, str) for domain in domain_list):
        raise HTTPException(status_code=400, detail="Domains must be provided as a list of valid strings")
    
    if len(domain_list) == 0:
        raise HTTPException(status_code=400, detail="At least one domain must be provided")
    
    try:
        batch_size = 5  # Process 5 domains at a time
        aggregated_domain_results = []
        
        # Process domains in batches to manage rate limiting
        for batch_start_index in range(0, len(domain_list), batch_size):
            current_batch = domain_list[batch_start_index:batch_start_index + batch_size]
            
            # Process current batch in parallel
            batch_processing_tasks = [
                get_domain_subdomains(domain_name) 
                for domain_name in current_batch
            ]
            batch_results = await asyncio.gather(*batch_processing_tasks, return_exceptions=True)
            
            # Process results and handle any exceptions
            for domain_name, subdomain_result in zip(current_batch, batch_results):
                if isinstance(subdomain_result, Exception):
                    # Log error but continue processing other domains
                    print(f"Error processing domain {domain_name}: {str(subdomain_result)}")
                    aggregated_domain_results.append({
                        "domain": domain_name, 
                        "subdomains": [],
                        "error": str(subdomain_result)
                    })
                else:
                    aggregated_domain_results.append({
                        "domain": domain_name, 
                        "subdomains": subdomain_result.subdomains
                    })
            
            # Rate limiting: wait between batches (except for the last batch)
            if batch_start_index + batch_size < len(domain_list):
                print(f"Processed batch {batch_start_index // batch_size + 1}, waiting 60 seconds before next batch...")
                await asyncio.sleep(60)
        
        return AggregatedDomainsResponse(aggregated_domains=aggregated_domain_results)
        
    except Exception as aggregation_error:
        raise HTTPException(
            status_code=500, 
            detail=f"Error during domain aggregation process: {str(aggregation_error)}"
        )