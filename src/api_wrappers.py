import json
import requests
import config
import uuid

from collections import Counter

SNUSBASE_API_KEY = config.SNUSBASE_API_KEY
SNUSBASE_URL = 'https://api-experimental.snusbase.com/'
SAVE_FILE = f"entries"
HEADERS = {
    'Auth': SNUSBASE_API_KEY,
    'Content-Type': 'application/json',
}


def save_response(response):
    id = str(uuid.uuid4())
    with open(f"{SAVE_FILE}/{id}", "w") as file:
        json.dump(response, file, indent=4)

    return id


def parse_data(response):
    data = []
    for result in response.get('results', {}).values():
        for entry in result:
            email = entry.get('email')
            if email:
                data.append(email)

    return list(set(data))


def send_request(endpoint, payload=None):
    """
    Send initial request to Snusbase API.

    :param endpoint: str - API endpoint
    :param payload: dict - Request body (Default: None)
    :return: dict - JSON response
    """
    method = 'POST' if payload else 'GET'
    data = json.dumps(payload) if payload else None
    response = requests.request(method, SNUSBASE_URL + endpoint, headers=HEADERS, data=data)

    if response.status_code == 200:
        return response.json()
    else:
        response.raise_for_status()


def whois(ips):
    """
    Performs a whois search on a list of IPs.

    :param ips: list - IPs to search
    :return: dict - Whois response
    """
    return send_request("tools/ip-whois", {"terms": ips})


def search(terms, types, wildcard=False):
    """
    Performs a generic snusbase lookup.

    :param terms: list - Search terms
    :param types: list - Data types
    :param wildcard: bool - Use wildcard search (Default: False)
    :return: dict - Search response
    """
    return send_request("data/search", {
        "terms": terms,
        "types": types,
        "wildcard": wildcard,
    })


def string_search(term, type, data):
    """
    Gathers data from a search()
    
    :param terms: list - Search terms
    :param types: list - Data types
    :param data: str - Return data
    :return: list - Parsed response data
    """
    response = search(term, type)
    items = []
    for key, value in response['results'].items():
        for record in value:
            if data in record:
                items.append(record[data])

    frequency = Counter(items)
    return_data = [item for item, count in frequency.items() if count <= 20]

    return return_data


def filter_by_location(term, types, country_code):
    """
    Matches search term with a country code if an IP is in query
    :param term: str - Single term
    :param types: list - Data types
    :return: dict - IP with geographical information
    """
    term_ips = string_search(term, types, "lastip")
    print(f"Found {len(term_ips)} IPs for term '{term}' before whois check.")
    
    CHUNK_SIZE = 100
    aggregated_ip_data = {'results': {}}

    for i in range(0, len(term_ips), CHUNK_SIZE):
        chunk = term_ips[i:i+CHUNK_SIZE]
        response = whois(chunk)
        print("Check done")
        if "results" in response:
            aggregated_ip_data["results"].update(response["results"])

    ip_data = aggregated_ip_data
    
    matching_data = []
    for ip, info in ip_data['results'].items():
        if info.get('countryCode') == country_code:
            data_entry = {
                'ip': ip,
                'country': info.get('country', 'Unknown'),
                'city': info.get('city', 'Unknown')
            }
            matching_data.append(data_entry)

    return matching_data