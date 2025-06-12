from bs4 import BeautifulSoup
import re

def get_all_certificates(html, remove_duplicates=False, subdomains_only=False):
    """
    Extracts all certificate information from the provided HTML content.

    Args:
        html (str): The HTML content containing certificate table information.
        remove_duplicates (bool): If True, remove duplicate certificates based on common name.
        subdomains_only (bool): If True, only return certificates for subdomains (domains with more than 2 dots).

    Returns:
        list: A list of dictionaries containing certificate information,
              or empty list if no certificates are found.
              
              Each dictionary contains:
              - crt_id (str): The certificate ID
              - logged_at (str|None): When the certificate was logged
              - not_before (str|None): Certificate validity start date
              - not_after (str|None): Certificate validity end date  
              - common_name (str|None): The common name
              - matching_identities (str|None): Matching identities/SANs
              - issuer_name (str|None): The certificate issuer
              
    Example:
        >>> html = '<table>...</table>'
        >>> get_all_certificates(html, remove_duplicates=True, subdomains_only=True)
        [
            {
                "crt_id": "18961771644",
                "logged_at": "2025-06-11",
                "not_before": "2025-06-11", 
                "not_after": "2025-09-09",
                "common_name": "api.megafree.xyz",
                "matching_identities": "api.megafree.xyz",
                "issuer_name": "C=US, O=Let's Encrypt, CN=E6"
            }
        ]
    """
    # Validate input
    if not html or not isinstance(html, str):
        return []
    
    soup = BeautifulSoup(html, 'html.parser')
    
    # Find the certificate table - look for table with certificate data
    table = None
    tables = soup.find_all('table')
    
    for t in tables:
        rows = t.find_all(['tr', 'TR'])
        if len(rows) < 2:
            continue
            
        # Check if this looks like a certificate table by looking at headers
        first_row = rows[0]
        headers = first_row.find_all(['th', 'TH'])
        
        if len(headers) >= 3:  # Need at least a few headers
            header_texts = [h.get_text(strip=True).lower() for h in headers]
            # Look for certificate-related headers
            if any('crt.sh id' in ht or 'id' in ht for ht in header_texts) and \
               any('common name' in ht or 'name' in ht for ht in header_texts):
                table = t
                break

    if not table:
        return []

    # Find all rows
    rows = table.find_all(['tr', 'TR'])

    if len(rows) < 2:  # Need at least header and one data row
        return []

    # Get headers to understand column structure
    header_row = rows[0]
    headers = header_row.find_all(['th', 'TH'])
    header_mapping = {}

    for i, header in enumerate(headers):
        header_text = header.get_text(strip=True).lower()
        # More precise header matching to avoid column shifts
        if 'crt.sh id' in header_text:
            header_mapping['crt_id'] = i
        elif 'logged at' in header_text:
            header_mapping['logged_at'] = i
        elif 'not before' in header_text:
            header_mapping['not_before'] = i
        elif 'not after' in header_text:
            header_mapping['not_after'] = i
        elif 'common name' in header_text and 'matching' not in header_text:
            header_mapping['common_name'] = i
        elif 'matching identities' in header_text:
            header_mapping['matching_identities'] = i
        elif 'issuer name' in header_text:
            header_mapping['issuer_name'] = i
        # Fallback for simpler headers if exact matches not found
        elif header_text == 'id' and i == 0 and 'crt_id' not in header_mapping:
            header_mapping['crt_id'] = i
    
    # Debug: print header mapping
    print(f"DEBUG: Header mapping: {header_mapping}")
    for i, header in enumerate(headers):
        print(f"DEBUG: Column {i}: '{header.get_text(strip=True)}'")

    # Extract data from table rows (skip header row)
    data_rows = rows[1:]
    certificates = []
    seen_common_names = set()
    
    for row_idx, row in enumerate(data_rows):
        cells = row.find_all(['td', 'TD'])
        print(f"DEBUG: Row {row_idx} has {len(cells)} cells")
        
        if len(cells) >= 3:  # Need at least a few cells
            cert_info = {
                "crt_id": None,
                "logged_at": None,
                "not_before": None,
                "not_after": None,
                "common_name": None,
                "matching_identities": None,
                "issuer_name": None
            }
            
            # Debug: print cell contents
            for i, cell in enumerate(cells):
                print(f"DEBUG: Row {row_idx}, Cell {i}: '{cell.get_text(strip=True)}'")
            
            # Use fixed column mapping based on the HTML structure:
            # 0: crt.sh ID, 1: Logged At, 2: Not Before, 3: Not After, 4: Common Name, 5: Matching Identities, 6: Issuer Name
            if len(cells) >= 7:  # Full table with all columns
                # Extract crt_id (column 0)
                crt_id_cell = cells[0]
                link = crt_id_cell.find('a')
                cert_info['crt_id'] = link.get_text(strip=True) if link else crt_id_cell.get_text(strip=True)
                
                # Extract other fields
                cert_info['logged_at'] = cells[1].get_text(strip=True) or None
                cert_info['not_before'] = cells[2].get_text(strip=True) or None  
                cert_info['not_after'] = cells[3].get_text(strip=True) or None
                cert_info['common_name'] = cells[4].get_text(strip=True) or None
                cert_info['matching_identities'] = cells[5].get_text(strip=True) or None
                
                # Extract issuer_name (column 6) - might be in a link
                issuer_cell = cells[6]
                issuer_link = issuer_cell.find('a')
                cert_info['issuer_name'] = issuer_link.get_text(strip=True) if issuer_link else issuer_cell.get_text(strip=True)
                
            else:
                # Fallback to header mapping for tables with fewer columns
                for field, col_index in header_mapping.items():
                    if col_index < len(cells):
                        cell = cells[col_index]
                        
                        if field == 'crt_id':
                            link = cell.find('a')
                            cert_info[field] = link.get_text(strip=True) if link else cell.get_text(strip=True)
                        elif field == 'issuer_name':
                            link = cell.find('a')
                            cert_info[field] = link.get_text(strip=True) if link else cell.get_text(strip=True)
                        else:
                            cert_info[field] = cell.get_text(strip=True) or None
            
            print(f"DEBUG: Row {row_idx} extracted data: {cert_info}")
            
            # Apply subdomain filter if requested
            if subdomains_only and cert_info["common_name"]:
                # Count dots in the domain name - fix the logic
                # For *.megafree.xyz, we want to include it as it's a subdomain wildcard
                domain = cert_info["common_name"]
                # Remove wildcard prefix if present
                if domain.startswith('*.'):
                    domain = domain[2:]
                
                dot_count = domain.count('.')
                # A subdomain should have MORE than 1 dot (e.g., api.megafree.xyz has 2 dots)
                # But *.megafree.xyz (wildcard) should also be included
                if dot_count <= 1 and not cert_info["common_name"].startswith('*.'):
                    print(f"DEBUG: Skipping {cert_info['common_name']} - not a subdomain")
                    continue
            
            # Apply duplicate removal if requested
            if remove_duplicates:
                if cert_info["common_name"] in seen_common_names:
                    continue
                if cert_info["common_name"]:
                    seen_common_names.add(cert_info["common_name"])
            
            certificates.append(cert_info)
    
    # Remove columns that are completely null/empty
    if certificates:
        # Check which columns have all null values
        columns_to_check = ["crt_id", "logged_at", "not_before", "not_after", "common_name", "matching_identities", "issuer_name"]
        columns_with_data = set()
        
        for cert in certificates:
            for col in columns_to_check:
                if cert.get(col) is not None and cert.get(col) != "":
                    columns_with_data.add(col)
        
        # Remove empty columns from all certificates
        cleaned_certificates = []
        for cert in certificates:
            cleaned_cert = {}
            for col in columns_to_check:
                if col in columns_with_data:
                    cleaned_cert[col] = cert[col]
            cleaned_certificates.append(cleaned_cert)
        
        return cleaned_certificates
    
    return certificates
