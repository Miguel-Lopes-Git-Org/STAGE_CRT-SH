from bs4 import BeautifulSoup

def get_cert_id(html):
    """
    Extracts certificate ID information from the provided HTML content.

    Args:
        html (str): The HTML content containing certificate ID information.

    Returns:
        str|None: The certificate ID from crt.sh, or None if not found.
              
    Example:
        >>> html = '<tr><th class="outer">crt.sh ID</th><td class="outer"><a href="?id=18872507865">18872507865</a></td></tr>'
        >>> get_cert_id(html)
        "18872507865"
    """
    soup = BeautifulSoup(html, 'html.parser')
    
    # Find the row containing crt.sh ID
    rows = soup.find_all('tr')
    
    for row in rows:
        # Find th and td elements in the row
        th_elements = row.find_all('th')
        td_elements = row.find_all('td')
        
        # Check if we have both th and td elements
        if th_elements and td_elements:
            for th in th_elements:
                header_text = th.get_text(strip=True).lower()
                
                # Look for crt.sh ID header
                if 'crt.sh id' in header_text:
                    # Find the corresponding td element
                    td = row.find('td', class_='outer')
                    if td:
                        # Extract ID from link or direct text
                        id_link = td.find('a')
                        cert_id = id_link.get_text(strip=True) if id_link else td.get_text(strip=True)
                        return cert_id
    
    return None