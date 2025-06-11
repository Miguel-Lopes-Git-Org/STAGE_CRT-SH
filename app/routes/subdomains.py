from fastapi import APIRouter, Request
from services.search import search
from services.cert_parser import parse_certificate_info, format_certificate_info
from bs4 import BeautifulSoup
import operator
from datetime import datetime
from pydantic import BaseModel
from typing import Optional
import asyncio

import os
import dotenv

# Load environment variables from .env file
dotenv.load_dotenv()

router = APIRouter()

def removeDoublons(lst):
    """
    Remove duplicate entries from a list.
    """
    return list(set(lst))

@router.get("/{domain}/subdomains")
async def get_subdomains(domain):
    """
    Retrieve a list of subdomains.
    """
    print(domain)

    if not domain or not isinstance(domain, str):
        raise ValueError("Domain is required and must be a string.")
    
    get_subdomains = search(os.getenv("BASE_URL") + "/?q=" + domain)

    html = BeautifulSoup(get_subdomains, "html.parser")

    subdomains = [td.get_text(strip=True) for td in html.select("tr td:nth-child(5)")
                  if td.get_text(strip=True).count('.') >= 2 and not td.get_text(strip=True).startswith('*.')]

    return removeDoublons(subdomains)


@router.get("/{domain}/subdomains/{subdomain}/certs")
def get_subdomain_certs(domain, subdomain):
    """
    Retrieve certificates for a specific subdomain.
    """
    
    if not domain or not isinstance(domain, str):
        raise ValueError("Domain is required and must be a string.")
    
    if not subdomain or not isinstance(subdomain, str):
        raise ValueError("Subdomain is required and must be a string.")

    try:
        get_subdomains = search(os.getenv("BASE_URL") + "/?q=" + domain)
    except Exception as e:
        raise ValueError(f"Error fetching subdomains: {e}")

    try:
        html = BeautifulSoup(get_subdomains, "html.parser")
    except Exception as e:
        raise ValueError(f"Error parsing HTML: {e}")

    try:
        cert = html.select_one(f"tr:has(td:-soup-contains('{subdomain}')) td:nth-child(1) a").get_text(strip=True)
    except Exception as e:
        raise ValueError(f"Error finding subdomain in HTML: {e}")

    # cert = cert_prettier(html.select_one("TD.text").get_text(strip=True))

    return { "certs": cert }

@router.get("/{domain}/subdomains/{subdomain}/latest")
def get_latest_subdomain_certs(domain, subdomain):
    """
    Retrieve the latest certificate for a specific subdomain.
    """
    
    if not domain or not isinstance(domain, str):
        raise ValueError("Domain is required and must be a string.")
    
    if not subdomain or not isinstance(subdomain, str):
        raise ValueError("Subdomain is required and must be a string.")

    try:
        get_subdomains = search(os.getenv("BASE_URL") + "/?q=" + domain)
    except Exception as e:
        raise ValueError(f"Error fetching subdomains: {e}")

    try:
        html = BeautifulSoup(get_subdomains, "html.parser")
    except Exception as e:
        raise ValueError(f"Error parsing HTML: {e}")

    subdomains = html.select("tr:has(td:nth-child(6)):not(:first-child)")

    # Filter certificates for the specific subdomain
    subdomain_certs = []
    for row in subdomains:
        if len(row.find_all('td')) >= 6:
            domain_name = row.find_all('td')[4].get_text(strip=True)
            if domain_name == subdomain:
                cert_info = {
                    "domain": domain_name,
                    "id": row.find_all('td')[0].get_text(strip=True),
                    "logged_at": row.find_all('td')[1].get_text(strip=True),
                    "not_before": row.find_all('td')[2].get_text(strip=True),
                    "not_after": row.find_all('td')[3].get_text(strip=True)
                }
                subdomain_certs.append(cert_info)

    if not subdomain_certs:
        raise ValueError(f"No certificates found for subdomain: {subdomain}")

    # Get the latest certificate based on not_before date
    latest_cert = max(subdomain_certs, 
                     key=lambda x: datetime.strptime(x['not_before'], '%Y-%m-%d'))

    return {"last_cert": latest_cert}


class OrderedRequest(BaseModel):
    revert: Optional[bool] = False

@router.post("/{domain}/subdomains/ordered")
def get_ordered_subdomain_certs(domain, body: OrderedRequest):
    """
    Retrieve the latest certificates for a specific domain.
    """

    revert_list = body.revert
    
    if not domain or not isinstance(domain, str):
        raise ValueError("Domain is required and must be a string.")

    try:
        get_subdomains = search(os.getenv("BASE_URL") + "/?q=" + domain)
    except Exception as e:
        raise ValueError(f"Error fetching subdomains: {e}")

    try:
        html = BeautifulSoup(get_subdomains, "html.parser")
    except Exception as e:
        raise ValueError(f"Error parsing HTML: {e}")

    subdomains = html.select("tr:has(td:nth-child(6)):not(:first-child)")

    certs_info = {
        row.find_all('td')[4].get_text(strip=True): {
            "id": row.find_all('td')[0].get_text(strip=True),
            "logged_at": row.find_all('td')[1].get_text(strip=True),
            "not_before": row.find_all('td')[2].get_text(strip=True),
            "not_after": row.find_all('td')[3].get_text(strip=True)
        }
        for row in subdomains 
        if len(row.find_all('td')) >= 6
    }

    # Trier par not_before (les dictionnaires en Python 3.7+ conservent l'ordre)
    sorted_certs = dict(sorted(certs_info.items(), 
                              key=lambda x: datetime.strptime(x[1]['not_before'], '%Y-%m-%d'), 
                              reverse=True if revert_list else False))

    return {"certs": sorted_certs}


@router.get("/{domain}/anomalies")
def get_anomalies(domain):
    """
    Retrieve anomalies for a specific domain.
    """
    
    if not domain or not isinstance(domain, str):
        raise ValueError("Domain is required and must be a string.")

    try:
        get_subdomains = search(os.getenv("BASE_URL") + "/?q=" + domain)
    except Exception as e:
        raise ValueError(f"Error fetching subdomains: {e}")

    try:
        html = BeautifulSoup(get_subdomains, "html.parser")
    except Exception as e:
        raise ValueError(f"Error parsing HTML: {e}")

    anomalies = html.select("tr:has(td:nth-child(6)):not(:first-child)")

    self_signed = {}
    expired = {}

    for row in anomalies:
        if len(row.find_all('td')) >= 6:
            cert_id = row.find_all('td')[0].get_text(strip=True)
            domain_name = row.find_all('td')[4].get_text(strip=True)
            not_after = row.find_all('td')[3].get_text(strip=True)
            
            # Check if certificate is expired
            try:
                expiry_date = datetime.strptime(not_after, '%Y-%m-%d')
                if expiry_date < datetime.now():
                    expired[domain_name] = {
                        "id": cert_id,
                        "logged_at": row.find_all('td')[1].get_text(strip=True),
                        "not_before": row.find_all('td')[2].get_text(strip=True),
                        "not_after": not_after
                    }
            except ValueError:
                pass
            
            # Fetch certificate details to check if self-signed
            try:
                certificatCompany = row.find_all("a")[1].get_text(strip=True).split("O=")[1].split(",")[0].replace('"', '')

                print(certificatCompany)

                selfSignedList = ["Let's Encrypt"]

                # Check if the certificate company is in the self-signed list
                if certificatCompany in selfSignedList:
                    self_signed[domain_name] = {
                        "id": cert_id,
                        "logged_at": row.find_all('td')[1].get_text(strip=True),
                        "not_before": row.find_all('td')[2].get_text(strip=True),
                        "not_after": not_after,
                        "issuer": certificatCompany
                    }
            except Exception:
                # Skip if certificate details cannot be fetched
                continue

    return {
        "self-signed": self_signed,
        "expired": expired
    }

class OrderedDomainsRequest(BaseModel):
    domains: Optional[list] = []

@router.post("/aggregate")
async def aggregate_domains(body: OrderedDomainsRequest):
    """
    Affregate domains from the request body.
    """
    
    try:
        print(body)
        domains = body.domains

        print(domains)
        
        if not isinstance(domains, list) or not all(isinstance(domain, str) for domain in domains):
            raise ValueError("Domains must be a list of strings.")
        
        batch_size = 5
        aggregated_domains = []
        
        for i in range(0, len(domains), batch_size):
            batch = domains[i:i + batch_size]
            
            # Process batch in parallel
            batch_results = await asyncio.gather(*[get_subdomains(domain) for domain in batch])
            
            # Add results
            aggregated_domains.extend([
                {"domain": domain, "subdomains": subdomains} 
                for domain, subdomains in zip(batch, batch_results)
            ])
            
            # Wait 20s between batches (except last one)
            if i + batch_size < len(domains):
                await asyncio.sleep(60)
        
        return {"aggregated_domains": aggregated_domains}
    
    except Exception as e:
        raise ValueError(f"Error processing request: {e}")