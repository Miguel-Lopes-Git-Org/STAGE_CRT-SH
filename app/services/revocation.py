from bs4 import BeautifulSoup

def get_revocation_info(html):
    """
    Extracts certificate revocation information from the provided HTML content.

    Args:
        html (str): The HTML content containing certificate revocation information.

    Returns:
        list: A list of dictionaries containing certificate revocation information,
              or empty list if the required table is not found.
              
              Each dictionary contains:
              - mechanism (str): The revocation mechanism (OCSP, CRL, etc.)
              - provider (str): The provider of the revocation service
              - status (str): The revocation status
              - revocation_date (str|None): The revocation date, or None if n/a
              - last_observed_in_crl (str|None): Last observed in CRL, or None if n/a
              - last_checked (str|None): Last checked timestamp, or None if n/a
              
    Example:
        >>> html = '<table class="options">...</table>'
        >>> get_revocation_info(html)
        [
            {
                "mechanism": "OCSP",
                "provider": "The CA",
                "status": "Check",
                "revocation_date": None,
                "last_observed_in_crl": None,
                "last_checked": None
            }
        ]
    """
    soup = BeautifulSoup(html, 'html.parser')
    
    # Find the table with revocation information - search by content, not just class
    table = None
    
    # Search all tables to find the one with revocation headers
    all_tables = soup.find_all('table')
    print(f"DEBUG: Total tables found: {len(all_tables)}")
    
    for i, t in enumerate(all_tables):
        print(f"DEBUG: Checking table {i}, class: {t.get('class')}, style: {t.get('style')}")
        
        # Find all rows in this table
        rows = t.find_all(['tr', 'TR'])
        if len(rows) < 2:
            print(f"DEBUG: Table {i} - Not enough rows ({len(rows)})")
            continue
            
        # Check the first row for headers
        first_row = rows[0]
        headers = first_row.find_all(['th', 'TH', 'td', 'TD'])  # Sometimes headers are in TD
        print(f"DEBUG: Table {i} - Found {len(headers)} potential headers")
        
        if len(headers) >= 6:
            header_texts = []
            for h in headers:
                header_text = h.get_text(separator=' ', strip=True)
                header_text = header_text.split('(')[0].strip()
                header_texts.append(header_text.lower())
                print(f"DEBUG: Table {i} - Header text: '{header_text}'")
            
            # Check if this looks like a revocation table
            has_mechanism = any('mechanism' in ht for ht in header_texts)
            has_provider = any('provider' in ht for ht in header_texts)
            has_status = any('status' in ht for ht in header_texts)
            
            print(f"DEBUG: Table {i} - Has mechanism: {has_mechanism}, provider: {has_provider}, status: {has_status}")
            
            if has_mechanism and has_provider and has_status:
                table = t
                print(f"DEBUG: Found revocation table at index {i}")
                break
        else:
            print(f"DEBUG: Table {i} - Not enough headers ({len(headers)})")
    
    print(f"DEBUG: Final table found: {table is not None}")
    if not table:
        print("DEBUG: No suitable revocation table found")
        return []
    
    # Find all rows
    rows = table.find_all(['tr', 'TR'])
    print(f"DEBUG: Number of rows found: {len(rows)}")
    
    if len(rows) < 2:  # Need at least header and one data row
        print("DEBUG: Not enough rows (need at least 2)")
        return []
    
    # Check if required headers are present in the first row - handle both cases
    header_row = rows[0]
    headers = header_row.find_all(['th', 'TH'])  # Handle both lowercase and uppercase
    print(f"DEBUG: Number of headers found: {len(headers)}")
    
    if len(headers) < 6:
        print(f"DEBUG: Not enough headers (need 6, found {len(headers)})")
        # Debug: print what we found in the first row
        print(f"DEBUG: First row content: {header_row}")
        return []
    
    # Verify all required headers exist (more flexible matching)
    header_texts = []
    for i, th in enumerate(headers):
        # Get text and clean it up, removing extra formatting
        header_text = th.get_text(separator=' ', strip=True)
        # Remove content in parentheses like "(Error)"
        header_text = header_text.split('(')[0].strip()
        header_texts.append(header_text)
        print(f"DEBUG: Header {i}: '{header_text}'")
    
    # More flexible header matching (case insensitive, partial match)
    if len(header_texts) < 6:
        print(f"DEBUG: Not enough header texts after processing")
        return []
    
    # Extract data from table rows (skip header row)
    data_rows = rows[1:]
    print(f"DEBUG: Number of data rows: {len(data_rows)}")
    revocation_entries = []
    
    for row_idx, row in enumerate(data_rows):
        cells = row.find_all(['td', 'TD'])  # Handle both cases
        print(f"DEBUG: Row {row_idx} has {len(cells)} cells")
        
        if len(cells) >= 6:
            # Extract mechanism (handle links)
            mechanism_cell = cells[0]
            mechanism_link = mechanism_cell.find('a')
            mechanism = mechanism_link.get_text(strip=True) if mechanism_link else mechanism_cell.get_text(strip=True)
            print(f"DEBUG: Row {row_idx} - Mechanism: '{mechanism}'")
            
            # Extract provider
            provider = cells[1].get_text(strip=True)
            print(f"DEBUG: Row {row_idx} - Provider: '{provider}'")
            
            # Extract status (handle links and clean text)
            status_cell = cells[2]
            status_link = status_cell.find('a')
            status = status_link.get_text(strip=True) if status_link else status_cell.get_text(strip=True)
            print(f"DEBUG: Row {row_idx} - Status: '{status}'")
            
            # Extract revocation date (convert n/a to None, handle SPAN elements)
            revocation_date_text = cells[3].get_text(strip=True)
            revocation_date = None if revocation_date_text in ['n/a', '?'] else revocation_date_text
            print(f"DEBUG: Row {row_idx} - Revocation Date: '{revocation_date_text}' -> {revocation_date}")
            
            # Extract last observed in CRL (convert n/a to None, handle SPAN elements)
            last_observed_text = cells[4].get_text(strip=True)
            last_observed_in_crl = None if last_observed_text in ['n/a', '?'] else last_observed_text
            print(f"DEBUG: Row {row_idx} - Last Observed in CRL: '{last_observed_text}' -> {last_observed_in_crl}")
            
            # Extract last checked (convert n/a to None, handle timestamps and SPAN elements)
            last_checked_cell = cells[5]
            last_checked_text = last_checked_cell.get_text(separator=' ', strip=True)
            print(f"DEBUG: Row {row_idx} - Last Checked raw: '{last_checked_text}'")
            if last_checked_text in ['n/a', '?']:
                last_checked = None
            else:
                # Clean up timestamp format
                last_checked = last_checked_text.replace('\xa0', ' ').replace('  ', ' ').strip()
                # If it's still just '?' after cleaning, set to None
                if last_checked == '?':
                    last_checked = None
            print(f"DEBUG: Row {row_idx} - Last Checked final: {last_checked}")
            
            entry = {
                "mechanism": mechanism,
                "provider": provider,
                "status": status,
                "revocation_date": revocation_date,
                "last_observed_in_crl": last_observed_in_crl,
                "last_checked": last_checked
            }
            print(f"DEBUG: Row {row_idx} - Final entry: {entry}")
            revocation_entries.append(entry)
        else:
            print(f"DEBUG: Row {row_idx} skipped - not enough cells")
    
    print(f"DEBUG: Total entries extracted: {len(revocation_entries)}")
    return revocation_entries