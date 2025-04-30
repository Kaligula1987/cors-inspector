#!/usr/bin/env python3

import httpx
import asyncio
from urllib.parse import urlparse
import warnings

warnings.filterwarnings("ignore")


async def parse_raw_request(raw_request):
    """
    Parse the raw HTTP request to extract the method, URL, headers, and body.
    """
    lines = [line.strip() for line in raw_request.strip().splitlines() if line.strip()]
    print("Raw Request Split into Lines:")
    print(lines)

    request_line = lines[0]
    headers = {}
    body = None

    method, path, _ = request_line.split()

    for i, line in enumerate(lines[1:]):
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()

    print("Parsed Headers:\n", headers)

    host = headers.get('Host')
    if not host:
        raise ValueError("❌ Error: Missing Host header in the request.")

    scheme = await test_scheme(host, path)
    url = f"{scheme}://{host}{path}"
    return method, url, headers, body


async def test_scheme(host, path):
    """
    Test if the website is reachable with both HTTP and HTTPS and return the appropriate scheme.
    """
    for scheme in ['https', 'http']:
        try:
            url = f"{scheme}://{host}{path}"
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                await client.get(url)
            return scheme
        except httpx.RequestError:
            continue
    return 'http'


async def analyze_cors_headers(resp_headers, origin):
    """
    Analyze CORS headers from the response and provide relevant findings.
    """
    findings = []
    allow_origin = resp_headers.get("Access-Control-Allow-Origin")
    allow_creds = resp_headers.get("Access-Control-Allow-Credentials")

    if allow_origin == origin:
        findings.append("🔴 Reflects Origin → vulnerable (could lead to data leakage)")
    elif allow_origin == "*":
        findings.append("🟠 Wildcard origin → less secure, potentially exposes sensitive data")

    if allow_creds == "true":
        if allow_origin in [origin, "*"]:
            findings.append("🔴 Dangerous configuration: Credentials + wildcard/origin reflection.")

    if not allow_origin and not allow_creds:
        findings.append("✅ No CORS headers found → Safe from cross-origin requests.")

    return findings


async def run_cors_test(method, url, headers, body):
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    origin = "http://evil.com"
    cookies = headers.get("Cookie", None)

    headers['Origin'] = origin
    headers['User-Agent'] = "cors-inspector"

    results = {}

    try:
        print(f"\n[+] Sending {method} with Origin to {base_url}")
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            r = await client.request(method=method, url=base_url, headers=headers, content=body or '', follow_redirects=True)
        results['METHOD'] = await analyze_cors_headers(r.headers, origin)
    except httpx.TimeoutException:
        results['METHOD'] = ["❌ Request timed out."]
    except httpx.RequestError as e:
        results['METHOD'] = [f"❌ Request failed: {str(e)}"]

    try:
        print("[+] Sending OPTIONS (preflight)...")
        opt_headers = headers.copy()
        opt_headers['Access-Control-Request-Method'] = 'POST'
        opt_headers['Access-Control-Request-Headers'] = 'Content-Type'

        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            r2 = await client.options(base_url, headers=opt_headers)
        results['OPTIONS'] = await analyze_cors_headers(r2.headers, origin)
    except httpx.TimeoutException:
        results['OPTIONS'] = ["❌ OPTIONS request timed out."]
    except httpx.RequestError as e:
        results['OPTIONS'] = [f"❌ OPTIONS request failed: {str(e)}"]

    if cookies:
        if any("vulnerable" in x or "DANGEROUS" in x for x in results['METHOD']):
            results['CookieRisk'] = [
                "🔐 Cookie present in request! 🚨",
                "⚠️ If cookies are HttpOnly and ACAO is misconfigured, an attacker could steal sensitive data!"
            ]

    return results, base_url, origin, cookies


async def print_summary(results, url, origin, cookies):
    print("\n======== 🛡️ CORS INSPECTION SUMMARY ========")
    print(f"🎯 Target URL: {url}")
    print(f"🌍 Origin used: {origin}")
    print(f"🍪 Cookies Detected: {'YES' if cookies else 'NO'}")

    print("\n📥 Main Request Analysis:")
    for line in results['METHOD']:
        print(f"  - {line}")

    print("\n📤 OPTIONS (Preflight) Analysis:")
    for line in results['OPTIONS']:
        print(f"  - {line}")

    if 'CookieRisk' in results:
        print("\n🚨 COOKIE RISK:")
        for line in results['CookieRisk']:
            print(f"  - {line}")

        print("\n💣 Exploit Example (JS for attacker site):")
        print(f"""
<script>
fetch("{url}", {{
  credentials: "include"
}})
.then(r => r.text())
.then(data => alert(data));
</script>
        """)

    # Detect safe wildcard-only CORS scenario
    all_findings = results['METHOD'] + results['OPTIONS']
    is_only_wildcard = all(
        "Wildcard origin" in finding or "No CORS headers" in finding
        for finding in all_findings
    ) and not any(
        "Credentials" in finding or "vulnerable" in finding or "Reflects Origin" in finding
        for finding in all_findings
    ) and not results.get("CookieRisk")

    if is_only_wildcard:
        print("\n✅ What was detected:")
        print("CORS headers are present and using a wildcard origin (*).")
        print("\nThat means any website can request this resource, which is generally okay only for public, non-sensitive content like static JS/CSS files.")
        print("\n⚠️ Mild concern:")
        print("Wildcard origin is flagged as 'less secure' — but not necessarily a vulnerability.")
        print("\nAs long as:\n")
        print("- There are no sensitive cookies shared,")
        print("- And Access-Control-Allow-Credentials is NOT set to true,")
        print("\n...then it’s generally acceptable.")

    print("\n💡 Recommendations:")
    if any("vulnerable" in line or "DANGEROUS" in line for line in results['METHOD'] + results['OPTIONS']):
        print("  - The site may be vulnerable to CORS misconfigurations. Further testing and mitigation are advised.")
    elif is_only_wildcard:
        print("  - Wildcard CORS config is okay for static content, but review its necessity.")
    else:
        print("  - No CORS misconfigurations were detected. Good job!")

    print("\n✅ Inspection Complete.")


async def main():
    print("📥 Paste raw HTTP request from Burp Suite, then press Ctrl+D (or Ctrl+Z on Windows):\n")
    try:
        raw = ''
        while True:
            raw += input() + '\n'
    except EOFError:
        pass

    try:
        method, url, headers, body = await parse_raw_request(raw)
        results, final_url, origin, cookies = await run_cors_test(method, url, headers, body)
        await print_summary(results, final_url, origin, cookies)
    except ValueError as ve:
        print(ve)
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
