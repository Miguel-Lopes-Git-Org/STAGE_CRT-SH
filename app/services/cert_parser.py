from bs4 import BeautifulSoup
import re
from typing import Dict, Any, List

def parse_certificate_info(html: str) -> Dict[str, Any]:
    """
    Parse certificate information from HTML format.
    """
    soup = BeautifulSoup(html, 'html.parser')
    
    # Find the TD element with class "text"
    td_element = soup.find('td', class_='text')
    if not td_element:
        return {}
    
    # Get the text content and split by <BR> tags
    html_content = str(td_element)
    html_content = re.sub(r'<BR[^>]*>', '\n', html_content, flags=re.IGNORECASE)
    
    # Remove HTML tags but keep the text
    soup_clean = BeautifulSoup(html_content, 'html.parser')
    text_content = soup_clean.get_text()
    
    # Split into lines and clean - replace \xa0 with regular spaces
    lines = [line.replace('\xa0', ' ').strip() for line in text_content.split('\n') if line.strip()]
    
    # Initialize result
    result = {"Certificate": {}}
    cert = result["Certificate"]
    
    # Parse each segment separately
    cert.update(parse_version(lines))
    cert.update(parse_serial_number(lines))
    cert.update(parse_signature_algorithm(lines))
    cert.update(parse_issuer(lines))
    cert.update(parse_validity(lines))
    cert.update(parse_subject(lines))
    cert.update(parse_subject_public_key_info(lines))
    cert.update(parse_x509v3_extensions(lines))
    cert.update(parse_authority_information_access(lines))
    cert.update(parse_subject_alternative_name(lines))
    cert.update(parse_certificate_policies(lines))
    cert.update(parse_crl_distribution_points(lines))
    cert.update(parse_ct_precertificate_poison(lines))
    cert.update(parse_final_signature(lines))
    
    return result

def parse_version(lines: List[str]) -> Dict[str, Any]:
    """Parse version information"""
    for line in lines:
        if line.startswith("Version:"):
            return {"Version": line.split(":", 1)[1].strip()}
    return {}

def parse_serial_number(lines: List[str]) -> Dict[str, Any]:
    """Parse serial number"""
    for i, line in enumerate(lines):
        if line.startswith("Serial Number:"):
            if i + 1 < len(lines):
                return {"Serial Number": lines[i + 1].strip()}
    return {}

def parse_signature_algorithm(lines: List[str]) -> Dict[str, Any]:
    """Parse first signature algorithm"""
    for line in lines:
        if line.startswith("Signature Algorithm:"):
            return {"Signature Algorithm": line.split(":", 1)[1].strip()}
    return {}

def parse_issuer(lines: List[str]) -> Dict[str, Any]:
    """Parse issuer information"""
    issuer = {}
    found_issuer = False
    
    for line in lines:
        if line.startswith("Issuer:"):
            found_issuer = True
            continue
        
        if found_issuer and "=" in line:
            if line == "Validity":
                break
            key, value = line.split("=", 1)
            issuer[key.strip()] = value.strip()
        elif found_issuer and line == "Validity":
            break
    
    return {"Issuer": issuer} if issuer else {}

def parse_validity(lines: List[str]) -> Dict[str, Any]:
    """Parse validity information"""
    validity = {}
    found_validity = False
    
    for line in lines:
        if line == "Validity":
            found_validity = True
            continue
        
        if found_validity:
            if line.startswith("Not Before:"):
                validity["Not Before"] = line.split(":", 1)[1].strip()
            elif line.startswith("Not After"):
                # Handle "Not After :" with space
                validity["Not After"] = ":".join(line.split(":")[1:]).strip()
            elif line == "Subject:":
                break
    
    return {"Validity": validity} if validity else {}

def parse_subject(lines: List[str]) -> Dict[str, Any]:
    """Parse subject information"""
    subject = {}
    found_subject = False
    
    for line in lines:
        if line == "Subject:":
            found_subject = True
            continue
        
        if found_subject and "=" in line:
            if line.startswith("Subject Public Key Info"):
                break
            key, value = line.split("=", 1)
            subject[key.strip()] = value.strip()
        elif found_subject and line.startswith("Subject Public Key Info"):
            break
    
    return {"Subject": subject} if subject else {}

def parse_subject_public_key_info(lines: List[str]) -> Dict[str, Any]:
    """Parse subject public key info"""
    spki = {}
    found_spki = False
    pub_values = []
    collecting_pub = False
    
    for line in lines:
        if line.startswith("Subject Public Key Info:"):
            found_spki = True
            continue
        
        if found_spki:
            if line.startswith("Public Key Algorithm:"):
                spki["Public Key Algorithm"] = line.split(":", 1)[1].strip()
            elif line.startswith("Public-Key:"):
                # Extract content inside parentheses - keep the format "(384 bit)"
                pub_key_part = line.split(":", 1)[1].strip()
                spki["Public-Key"] = pub_key_part
            elif line == "pub:":
                collecting_pub = True
                pub_values = []
                continue
            elif collecting_pub and re.match(r'^[0-9a-f]{2}:', line):
                pub_values.append(line)
            elif collecting_pub and not re.match(r'^[0-9a-f]{2}:', line):
                collecting_pub = False
                if pub_values:
                    spki["pub"] = pub_values
                # Continue processing the current line
                if line.startswith("ASN1 OID:"):
                    spki["ASN1 OID"] = line.split(":", 1)[1].strip()
                elif line.startswith("NIST CURVE:"):
                    spki["NIST CURVE"] = line.split(":", 1)[1].strip()
            elif line.startswith("ASN1 OID:"):
                spki["ASN1 OID"] = line.split(":", 1)[1].strip()
            elif line.startswith("NIST CURVE:"):
                spki["NIST CURVE"] = line.split(":", 1)[1].strip()
            elif line.startswith("X509v3 extensions:"):
                if collecting_pub and pub_values:
                    spki["pub"] = pub_values
                break
    
    return {"Subject Public Key Info": spki} if spki else {}

def parse_x509v3_extensions(lines: List[str]) -> Dict[str, Any]:
    """Parse X509v3 extensions"""
    extensions = {}
    found_extensions = False
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        if line.startswith("X509v3 extensions:"):
            found_extensions = True
            i += 1
            continue
        
        if found_extensions:
            if line.startswith("X509v3 Key Usage:"):
                extensions["X509v3 Key Usage"] = {
                    "critical": "critical" in line,
                    "usages": []
                }
                i += 1
                while i < len(lines) and not lines[i].startswith("X509v3") and not lines[i].startswith("Authority") and ":" not in lines[i]:
                    if lines[i].strip():
                        extensions["X509v3 Key Usage"]["usages"].append(lines[i].strip())
                    i += 1
                continue
                
            elif line.startswith("X509v3 Extended Key Usage:"):
                extensions["X509v3 Extended Key Usage"] = []
                i += 1
                while i < len(lines) and not lines[i].startswith("X509v3") and not lines[i].startswith("Authority") and ":" not in lines[i]:
                    if lines[i].strip():
                        if ", " in lines[i]:
                            extensions["X509v3 Extended Key Usage"].extend([u.strip() for u in lines[i].split(",")])
                        else:
                            extensions["X509v3 Extended Key Usage"].append(lines[i].strip())
                    i += 1
                continue
                
            elif line.startswith("X509v3 Basic Constraints:"):
                extensions["X509v3 Basic Constraints"] = {
                    "critical": "critical" in line,
                    "CA": False
                }
                i += 1
                if i < len(lines) and "CA:" in lines[i]:
                    ca_value = lines[i].split(":", 1)[1].strip()
                    extensions["X509v3 Basic Constraints"]["CA"] = ca_value.upper() == "TRUE"
                    i += 1
                continue
                
            elif line.startswith("X509v3 Subject Key Identifier:"):
                i += 1
                if i < len(lines):
                    extensions["X509v3 Subject Key Identifier"] = lines[i].strip()
                    i += 1
                continue
                
            elif line.startswith("X509v3 Authority Key Identifier:"):
                i += 1
                if i < len(lines) and "keyid:" in lines[i]:
                    keyid_value = lines[i].replace("keyid:", "").strip()
                    extensions["X509v3 Authority Key Identifier"] = {"keyid": keyid_value}
                    i += 1
                continue
                
            elif line.startswith("Authority Information Access:"):
                break
        
        i += 1
    
    return {"X509v3 extensions": extensions} if extensions else {}

def parse_authority_information_access(lines: List[str]) -> Dict[str, Any]:
    """Parse Authority Information Access"""
    for i, line in enumerate(lines):
        if line.startswith("Authority Information Access:"):
            if i + 1 < len(lines) and "CA Issuers" in lines[i + 1]:
                ca_issuers = lines[i + 1].replace("CA Issuers - ", "").strip()
                return {"Authority Information Access": {"CA Issuers": ca_issuers}}
    return {}

def parse_subject_alternative_name(lines: List[str]) -> Dict[str, Any]:
    """Parse X509v3 Subject Alternative Name"""
    san_list = []
    found_san = False
    
    for line in lines:
        if line.startswith("X509v3 Subject Alternative Name:"):
            found_san = True
            continue
        
        if found_san:
            if line.startswith("X509v3") or line.startswith("CT Pre") or line.endswith(":"):
                break
            if line.strip():
                san_list.append(line.strip())
    
    return {"X509v3 Subject Alternative Name": san_list} if san_list else {}

def parse_certificate_policies(lines: List[str]) -> Dict[str, Any]:
    """Parse X509v3 Certificate Policies"""
    for i, line in enumerate(lines):
        if line.startswith("X509v3 Certificate Policies:"):
            if i + 1 < len(lines) and "Policy:" in lines[i + 1]:
                policy_value = lines[i + 1].replace("Policy:", "").strip()
                return {"X509v3 Certificate Policies": {"Policy": policy_value}}
    return {}

def parse_crl_distribution_points(lines: List[str]) -> Dict[str, Any]:
    """Parse X509v3 CRL Distribution Points"""
    found_crl = False
    
    for line in lines:
        if line.startswith("X509v3 CRL Distribution Points:"):
            found_crl = True
            continue
        
        if found_crl:
            if line.startswith("URI:"):
                return {"X509v3 CRL Distribution Points": {"Full Name": line.strip()}}
            elif line.strip() and not line.startswith("Full Name:"):
                # Skip "Full Name:" line, look for URI
                continue
    
    return {}

def parse_ct_precertificate_poison(lines: List[str]) -> Dict[str, Any]:
    """Parse CT Precertificate Poison"""
    for line in lines:
        if "CT Precertificate" in line and "Poison:" in line:
            return {"CT Precertificate Poison": {
                "critical": "critical" in line,
                "value": "NULL"
            }}
    return {}

def parse_final_signature(lines: List[str]) -> Dict[str, Any]:
    """Parse final signature - look for lines after the last section"""
    signature_lines = []
    
    # Find lines after CT Precertificate Poison that are hex patterns
    found_ct = False
    for i, line in enumerate(lines):
        if "CT Precertificate" in line and "Poison:" in line:
            found_ct = True
            continue
        
        if found_ct:
            # Skip NULL line
            if line == "NULL":
                continue
            # Look for Signature Algorithm (second occurrence)
            if line.startswith("Signature Algorithm:"):
                continue
            # Collect hex signature lines
            if re.match(r'^[0-9a-f]{2}:', line):
                signature_lines.append(line.strip())
    
    return {"Signature": signature_lines} if signature_lines else {}

def format_certificate_info(cert_info: Dict) -> Dict:
    """Format the parsed certificate information for better readability."""
    return cert_info