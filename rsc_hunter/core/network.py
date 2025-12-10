import requests
from requests.exceptions import RequestException
from urllib.parse import urlparse

def parse_headers(header_list: list[str] | None) -> dict[str, str]:
    """Parse a list of 'Key: Value' strings into a dict."""
    headers = {}
    if not header_list:
        return headers
    for header in header_list:
        if ": " in header:
            key, value = header.split(": ", 1)
            headers[key] = value
        elif ":" in header:
            key, value = header.split(":", 1)
            headers[key] = value.lstrip()
    return headers

def normalize_host(host: str) -> str:
    """Normalize host to include scheme if missing."""
    host = host.strip()
    if not host:
        return ""
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    return host.rstrip("/")

def resolve_redirects(url: str, timeout: int, verify_ssl: bool, max_redirects: int = 10) -> str:
    """Follow redirects only if they stay on the same host."""
    current_url = url
    original_host = urlparse(url).netloc

    for _ in range(max_redirects):
        try:
            response = requests.head(
                current_url,
                timeout=timeout,
                verify=verify_ssl,
                allow_redirects=False
            )
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if location:
                    if location.startswith("/"):
                        # Relative redirect - same host, safe to follow
                        parsed = urlparse(current_url)
                        current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
                    else:
                        # Absolute redirect - check if same host
                        new_host = urlparse(location).netloc
                        if new_host == original_host:
                            current_url = location
                        else:
                            break  # Different host, stop following
                else:
                    break
            else:
                break
        except RequestException:
            break
    return current_url

def send_payload(target_url: str, headers: dict, body: str, timeout: int, verify_ssl: bool) -> tuple[requests.Response | None, str | None]:
    """Send the exploit payload to a URL. Returns (response, error)."""
    try:
        # Encode body as bytes to ensure proper Content-Length calculation
        body_bytes = body.encode('utf-8') if isinstance(body, str) else body
        response = requests.post(
            target_url,
            headers=headers,
            data=body_bytes,
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=False
        )
        return response, None
    except requests.exceptions.SSLError as e:
        return None, f"SSL Error: {str(e)}"
    except requests.exceptions.ConnectionError as e:
        return None, f"Connection Error: {str(e)}"
    except requests.exceptions.Timeout:
        return None, "Request timed out"
    except RequestException as e:
        return None, f"Request failed: {str(e)}"
    except Exception as e:
        return None, f"Unexpected error: {str(e)}"
