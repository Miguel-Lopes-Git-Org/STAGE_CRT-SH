from bs4 import BeautifulSoup

def get_certificate_fingerprints(html):
    """
    Extracts certificate fingerprint information (SHA-1 and SHA-256) from the provided HTML content.

    Args:
        html (str): The HTML content containing certificate fingerprint information.

    Returns:
        dict: A dictionary containing certificate fingerprints, or empty dict if not found.
              
              The dictionary contains:
              - sha1 (str|None): The SHA-1 fingerprint, or None if not found
              - sha256 (str|None): The SHA-256 fingerprint, or None if not found
              
    Example:
        >>> html = '<table class="options">...</table>'
        >>> get_certificate_fingerprints(html)
        {
            "sha1": "14CE37895292AEDC52985E5EA85B8F3A52CFA8A5",
            "sha256": "A60C802959EC14CD5989043660905903D6436D0119C39715D71F316B3EF3A631"
        }
    """
    soup = BeautifulSoup(html, 'html.parser')
    
    result = {
        "sha1": None,
        "sha256": None
    }
    
    # Find all tables
    tables = soup.find_all('table')
    
    for table in tables:
        # Find all rows
        rows = table.find_all(['tr', 'TR'])
        
        for row in rows:
            # Find all cells (TH and TD)
            cells = row.find_all(['th', 'TH', 'td', 'TD'])
            
            # Look for SHA-1 and SHA-256 headers
            for i, cell in enumerate(cells):
                cell_text = cell.get_text(strip=True).upper()
                
                if cell_text == 'SHA-1' and i + 1 < len(cells):
                    # Get the next cell which should contain the SHA-1 value  
                    sha1_cell = cells[i + 1]
                    sha1_text = sha1_cell.get_text(strip=True)
                    if sha1_text and len(sha1_text) == 40:  # SHA-1 is 40 hex chars
                        result["sha1"] = sha1_text.upper()
                
                elif cell_text == 'SHA-256' and i + 1 < len(cells):
                    # Get the next cell which should contain the SHA-256 value
                    sha256_cell = cells[i + 1]
                    # Handle both direct text and links
                    sha256_link = sha256_cell.find('a')
                    if sha256_link:
                        sha256_text = sha256_link.get_text(strip=True)
                    else:
                        sha256_text = sha256_cell.get_text(strip=True)
                    
                    if sha256_text and len(sha256_text) == 64:  # SHA-256 is 64 hex chars
                        result["sha256"] = sha256_text.upper()
    
    return result
