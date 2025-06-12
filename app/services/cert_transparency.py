from bs4 import BeautifulSoup

def get_certificat_transparency(html):
    """
    Extracts certificate transparency log information from the provided HTML content.

    Args:
        html (str): The HTML content containing certificate transparency log information.

    Returns:
        list: A list of dictionaries containing certificate transparency log information,
              or empty list if the required table is not found.
              
              Each dictionary contains:
              - timestamp (str): The timestamp when the certificate was logged
              - entry_number (str): The entry number in the log
              - log_operator (str): The operator of the certificate transparency log
              - log_url (str): The URL of the certificate transparency log
              
    Example:
        >>> html = '<table class="options">...</table>'
        >>> get_certificat_transparency(html)
        [
            {
                "timestamp": "2025-06-07 14:19:42 UTC",
                "entry_number": "977398340",
                "log_operator": "Google",
                "log_url": "https://ct.googleapis.com/logs/us1/argon2025h2"
            }
        ]
    """
    soup = BeautifulSoup(html, 'html.parser')
    
    # Find the table with certificate transparency log data
    table = soup.find('table', class_='options')
    
    if not table:
        return []
    
    # Find all rows and skip the first two (description and headers)
    rows = table.find_all('tr')
    
    if len(rows) < 3:  # Need at least description, header, and one data row
        return []
    
    # Check if required headers are present in the second row
    header_row = rows[1]
    headers = header_row.find_all('th')
    required_headers = ['Timestamp', 'Entry #', 'Log Operator', 'Log URL']
    
    if len(headers) < 4:
        return []
    
    # Verify all required headers exist
    header_texts = [th.get_text(strip=True) for th in headers]
    if not all(required_header in header_texts for required_header in required_headers):
        return []
    
    # Extract data from table rows (skip first two rows: description and headers)
    data_rows = rows[2:]
    log_entries = []
    
    for row in data_rows:
        cells = row.find_all('td')
        if len(cells) >= 4:
            # Extract timestamp (combine date and time)
            timestamp_cell = cells[0]
            timestamp_text = timestamp_cell.get_text(strip=True)
            # Clean up timestamp format
            timestamp = timestamp_text.replace('\xa0', ' ').replace('  ', ' ')
            
            # Extract other information
            entry_number = cells[1].get_text(strip=True)
            log_operator = cells[2].get_text(strip=True)
            log_url = cells[3].get_text(strip=True)
            
            log_entries.append({
                "timestamp": timestamp,
                "entry_number": entry_number,
                "log_operator": log_operator,
                "log_url": log_url
            })
    
    return log_entries