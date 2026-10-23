"""
Hikvision camera checks.

A small known-default credential test over digest auth, plus detection of
two well-known CVEs. Detection only - no RCE payloads are fired and no
configuration is modified beyond a benign language-set probe.
"""
import requests
from requests.auth import HTTPDigestAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Known Hikvision factory defaults - a small set, not a brute force.
HIK_DEFAULT_CREDS = [
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "Admin12345"),
    ("admin", "admin12345"),
]


def test_default_creds(ip, timeout=5):
    """Try the known-default credentials over digest auth. Returns the first hit."""
    for user, pw in HIK_DEFAULT_CREDS:
        try:
            r = requests.get(
                f"http://{ip}/ISAPI/System/deviceInfo",
                auth=HTTPDigestAuth(user, pw),
                timeout=timeout, verify=False,
            )
            if r.status_code == 200:
                return {"user": user, "password": pw}
        except Exception:
            pass
    return None


def check_cve_2017_7921(ip, timeout=5):
    """
    CVE-2017-7921 auth bypass: appending ?auth=YWRtaW46MTEK exposes ISAPI
    endpoints without authentication. Read-only detection.
    """
    try:
        r = requests.get(
            f"http://{ip}/Security/users?auth=YWRtaW46MTEK",
            timeout=timeout, verify=False,
        )
        vuln = r.status_code == 200 and "<UserList" in (r.text or "")
        return {"vulnerable": vuln, "status": r.status_code, "error": None}
    except Exception as e:
        return {"vulnerable": False, "status": None, "error": str(e)}


def check_cve_2021_36260(ip, timeout=5):
    """
    CVE-2021-36260: the /SDK/webLanguage handler lacks authentication on
    unpatched firmware. Detection only - sends a benign `<language>en</language>`
    PUT and inspects auth handling. A 200 + statusString OK means the endpoint
    is exposed unauthenticated (RCE precondition); 401 means patched.

    This does NOT confirm RCE - that requires a separate time-based probe.
    """
    body = '<?xml version="1.0" encoding="UTF-8"?>\r\n<language>en</language>'
    try:
        r = requests.put(
            f"http://{ip}/SDK/webLanguage", data=body,
            timeout=timeout, verify=False,
        )
        exposed = r.status_code == 200 and "OK" in (r.text or "")
        return {"endpoint_exposed": exposed, "status": r.status_code,
                "rce_confirmed": False, "error": None}
    except Exception as e:
        return {"endpoint_exposed": False, "status": None,
                "rce_confirmed": False, "error": str(e)}


def assess_hikvision(ip, test_creds=True):
    """Run the Hikvision checks against `ip`. Returns a structured findings dict."""
    result = {
        "service": "hikvision",
        "host": ip,
        "default_creds": None,
        "cve_2017_7921": None,
        "cve_2021_36260": None,
    }
    if test_creds:
        result["default_creds"] = test_default_creds(ip)
        result["cve_2017_7921"] = check_cve_2017_7921(ip)
        result["cve_2021_36260"] = check_cve_2021_36260(ip)
    return result
