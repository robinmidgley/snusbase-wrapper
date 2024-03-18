from src.api_wrappers import (
    whois,
    search,
    string_search,
    filter_by_location,
    save_response,
)

# Example
resp = filter_by_location(["Robin"], ["username"], "GB")
save_response(resp)