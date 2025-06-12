from bs4 import BeautifulSoup
import re
from typing import Dict, Any, List, Optional

def get_ca_id(html: str) -> Optional[str]:
    """
    Extract crt.sh CA ID from HTML.
    
    Args:
        html (str): HTML content containing CA ID information
        
    Returns:
        Optional[str]: CA ID or None if not found
    """
    if not html or not isinstance(html, str):
        return None
        
    soup = BeautifulSoup(html, 'html.parser')
    
    # Find TR with TH containing "crt.sh CA ID"
    rows = soup.find_all('tr')
    for row in rows:
        th = row.find('th', class_='outer')
        if th and 'crt.sh CA ID' in th.get_text(strip=True):
            td = row.find('td', class_='outer')
            if td:
                return td.get_text(strip=True)
    
    return None

def get_ca_subject_info(html: str) -> Dict[str, Any]:
    """
    Extract CA subject and public key information from HTML.
    
    Args:
        html (str): HTML content containing CA subject information
        
    Returns:
        Dict[str, Any]: Parsed subject and public key information
    """
    if not html or not isinstance(html, str):
        return {}
        
    soup = BeautifulSoup(html, 'html.parser')
    
    # Find TD with class "text"
    td_element = soup.find('td', class_='text')
    if not td_element:
        return {}
    
    # Get the text content and split by <BR> tags
    html_content = str(td_element)
    html_content = re.sub(r'<BR[^>]*>', '\n', html_content, flags=re.IGNORECASE)
    
    # Remove HTML tags but keep the text
    soup_clean = BeautifulSoup(html_content, 'html.parser')
    text_content = soup_clean.get_text()
    
    # Split into lines and clean
    lines = [line.replace('\xa0', ' ').strip() for line in text_content.split('\n') if line.strip()]
    
    result = {}
    
    # Parse Subject
    subject = {}
    found_subject = False
    
    for line in lines:
        if line.startswith("Subject:"):
            found_subject = True
            continue
            
        if found_subject and "=" in line:
            if line.startswith("Subject Public Key Info"):
                break
            key, value = line.split("=", 1)
            subject[key.strip()] = value.strip()
        elif found_subject and line.startswith("Subject Public Key Info"):
            break
    
    if subject:
        result["Subject"] = subject
    
    # Parse Subject Public Key Info
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
            elif "Public-Key:" in line or "RSA Public-Key:" in line:
                # Extract key size info
                if "(" in line and ")" in line:
                    key_info = line.split(":", 1)[1].strip()
                    spki["Public-Key"] = key_info
            elif line == "Modulus:" or line.strip() == "Modulus:":
                collecting_pub = True
                pub_values = []
                continue
            elif collecting_pub and re.match(r'^[0-9a-f]{2}:', line):
                pub_values.append(line.strip())
            elif collecting_pub and line.startswith("Exponent:"):
                collecting_pub = False
                if pub_values:
                    spki["Modulus"] = pub_values
                spki["Exponent"] = line.split(":", 1)[1].strip()
                break
    
    if spki:
        result["Subject Public Key Info"] = spki
    
    return result

def get_certificates(html: str) -> List[Dict[str, Any]]:
    """
    Extract certificates information from HTML table.
    
    Args:
        html (str): HTML content containing certificates table
        
    Returns:
        List[Dict[str, Any]]: List of certificates
    """
    if not html or not isinstance(html, str):
        return []
        
    soup = BeautifulSoup(html, 'html.parser')
    
    # Find table with class "options"
    table = soup.find('table', class_='options')
    if not table:
        return []
    
    rows = table.find_all('tr')
    if len(rows) < 2:
        return []
    
    # Get headers
    header_row = rows[0]
    headers = header_row.find_all('th')
    header_texts = [h.get_text(strip=True) for h in headers]
    
    # Extract data
    certificates = []
    for row in rows[1:]:
        cells = row.find_all('td')
        if len(cells) >= len(header_texts):
            cert_info = {}
            
            for i, header in enumerate(header_texts):
                if i < len(cells):
                    cell = cells[i]
                    
                    # Handle links
                    link = cell.find('a')
                    if link:
                        cert_info[header] = link.get_text(strip=True)
                    else:
                        cert_info[header] = cell.get_text(strip=True)
            
            certificates.append(cert_info)
    
    return certificates

def get_population_stats(html: str) -> Dict[str, Any]:
    """
    Extract population statistics from HTML table.
    
    Args:
        html (str): HTML content containing population statistics table
        
    Returns:
        Dict[str, Any]: Population statistics
    """
    if not html or not isinstance(html, str):
        return {}
        
    soup = BeautifulSoup(html, 'html.parser')
    
    # Find the population table (first table with Population header)
    tables = soup.find_all('table', class_='options')
    population_table = None
    
    for table in tables:
        rows = table.find_all('tr')
        if rows and len(rows) > 0:
            first_row = rows[0]
            headers = first_row.find_all('th')
            if headers and 'Population' in headers[0].get_text(strip=True):
                population_table = table
                break
    
    if not population_table:
        return {}
    
    rows = population_table.find_all('tr')
    if len(rows) < 2:
        return {}
    
    result = {}
    
    for row in rows[1:]:  # Skip header row
        cells = row.find_all('td')
        if len(cells) >= 4:
            category = cells[0].get_text(strip=True)
            unexpired = cells[1].get_text(strip=True)
            expired = cells[2].get_text(strip=True)
            total = cells[3].get_text(strip=True)
            
            result[category] = {
                "Unexpired": unexpired,
                "Expired": expired,
                "Total": total
            }
    
    return {"Population": result} if result else {}

def get_trust_info(html: str) -> Dict[str, Any]:
    """
    Extract trust information from HTML table.
    
    Args:
        html (str): HTML content containing trust information table
        
    Returns:
        Dict[str, Any]: Trust information by purpose and context
    """
    if not html or not isinstance(html, str):
        return {}
        
    soup = BeautifulSoup(html, 'html.parser')
    
    # Find the trust table (table with Purpose header)
    tables = soup.find_all('table', class_='options')
    trust_table = None
    
    for table in tables:
        rows = table.find_all('tr')
        if len(rows) >= 2:
            # Check if this is the trust table by looking for "Purpose" in first column
            for row in rows:
                cells = row.find_all(['th', 'td'])
                if cells and 'Purpose' in cells[0].get_text(strip=True):
                    trust_table = table
                    break
            if trust_table:
                break
    
    if not trust_table:
        return {}
    
    rows = trust_table.find_all('tr')
    if len(rows) < 3:  # Need header rows + data rows
        return {}
    
    # Get context headers from second row
    context_row = rows[1]
    context_headers = context_row.find_all('th')
    contexts = []
    for th in context_headers:
        # Extract main context name (e.g., "360 Browser", "Apple", etc.)
        link = th.find('a')
        if link:
            contexts.append(link.get_text(strip=True))
        else:
            contexts.append(th.get_text(strip=True))
    
    # Extract trust data
    trust_data = {}
    
    for row in rows[2:]:  # Skip header rows
        cells = row.find_all('td')
        if len(cells) >= len(contexts) + 1:  # +1 for purpose column
            purpose = cells[0].get_text(strip=True)
            purpose_data = {}
            
            for i, context in enumerate(contexts):
                if i + 1 < len(cells):
                    cell = cells[i + 1]
                    # Extract the actual value (Yes/No/n/a)
                    font = cell.find('font')
                    if font:
                        value = font.get_text(strip=True)
                    else:
                        value = cell.get_text(strip=True)
                    
                    purpose_data[context] = value
            
            trust_data[purpose] = purpose_data
    
    return {"Trust": trust_data} if trust_data else {}

def get_parent_child_cas(html: str) -> Dict[str, Any]:
    """
    Extract parent and child CA information from HTML.
    
    Args:
        html (str): HTML content containing parent/child CA information
        
    Returns:
        Dict[str, Any]: Parent and child CA information
    """
    if not html or not isinstance(html, str):
        return {}
        
    soup = BeautifulSoup(html, 'html.parser')
    
    result = {}
    
    # Find rows with Parent CAs and Child CAs
    rows = soup.find_all('tr')
    
    for row in rows:
        th = row.find('th', class_='outer')
        if th:
            th_text = th.get_text(strip=True)
            td = row.find('td', class_='outer')
            
            if td:
                td_text = td.get_text(strip=True)
                
                if 'Parent CAs' in th_text:
                    if 'None found' in td_text:
                        result['Parent_CAs'] = None
                    else:
                        result['Parent_CAs'] = td_text
                
                elif 'Child CAs' in th_text:
                    if 'None found' in td_text:
                        result['Child_CAs'] = None
                    else:
                        result['Child_CAs'] = td_text
    
    return result

def get_all_ca_info(html: str) -> Dict[str, Any]:
    """
    Extract all CA information from HTML.
    
    Args:
        html (str): Complete HTML content for CA page
        
    Returns:
        Dict[str, Any]: Complete CA information
    """
    if not html or not isinstance(html, str):
        return {}
    
    result = {}
    
    # Extract each section
    ca_id = get_ca_id(html)
    if ca_id:
        result['ca_id'] = ca_id
    
    subject_info = get_ca_subject_info(html)
    if subject_info:
        result.update(subject_info)
    
    issued_certs = get_certificates(html)
    if issued_certs:
        result['certificates'] = issued_certs
    
    population = get_population_stats(html)
    if population:
        result.update(population)
    
    trust_info = get_trust_info(html)
    if trust_info:
        result.update(trust_info)
    
    parent_child = get_parent_child_cas(html)
    if parent_child:
        result.update(parent_child)
    
    return result
