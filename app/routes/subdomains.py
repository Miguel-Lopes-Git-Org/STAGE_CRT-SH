from fastapi import APIRouter
from services.search import search
from services.cert_parser import parse_certificate_info, format_certificate_info
from bs4 import BeautifulSoup
import operator
from datetime import datetime

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

@router.get("/{domain}/subdomains/latest")
def get_latest_subdomain_certs(domain):
    """
    Retrieve the latest certificates for a specific domain.
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
                              reverse=True))

    return {"certs": sorted_certs}