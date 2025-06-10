import requests

def search(url):

    result = requests.get(url)
    
    if result.status_code == 200:
        return result.text
    else:
        raise Exception(f"Error fetching data from {url}: {result.status_code} - {result.text}")