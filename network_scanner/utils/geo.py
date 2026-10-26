"""
External IP Geolocation and Network Intelligence Service.
Queries public ASN, Organization, Country, City, and Coordinates.
Uses zero external libraries (standard Python urllib and json).
"""

import json
import ipaddress
import urllib.request
import urllib.error

_GEO_CACHE = {}


def is_public_ip(ip):
    """
    Checks if an IP address is publicly routable on the WAN.
    Returns False for RFC1918 private, loopback, link-local, multicast, or reserved IPs.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if (ip_obj.is_private or ip_obj.is_loopback or 
                ip_obj.is_link_local or ip_obj.is_reserved or 
                ip_obj.is_multicast or ip_obj.is_unspecified):
            return False
        return True
    except ValueError:
        return False


def get_ip_geolocation(ip, timeout=3):
    """
    Retrieves IP geolocation and ISP/AS metadata for public IP addresses.
    Uses an in-memory cache to prevent redundant network requests.

    Returns:
        dict: Geolocation metadata or status indicating private/failed lookup.
    """
    if not is_public_ip(ip):
        return {
            "status": "private",
            "ip": ip,
            "message": "Private / Local Area Network IP"
        }

    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "NetworkScanner/2.0"}
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                data = json.loads(response.read().decode("utf-8"))
                if data.get("status") == "success":
                    city = data.get("city", "")
                    country = data.get("country", "")
                    org = data.get("org") or data.get("isp", "")
                    as_num = data.get("as", "")
                    
                    loc_parts = [p for p in (city, country) if p]
                    loc_str = ", ".join(loc_parts)
                    org_parts = [p for p in (org, as_num) if p]
                    org_str = " | ".join(org_parts)
                    
                    data["summary"] = f"{loc_str} ({org_str})" if org_str else loc_str
                    _GEO_CACHE[ip] = data
                    return data
                else:
                    res = {"status": "fail", "ip": ip, "message": data.get("message", "Lookup failed")}
                    _GEO_CACHE[ip] = res
                    return res
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as err:
        return {
            "status": "fail",
            "ip": ip,
            "message": f"Network error: {err}"
        }

    return {"status": "fail", "ip": ip, "message": "Unknown error"}


def format_geo_banner(geo_data):
    """Formats geolocation information into a clean terminal banner."""
    if not geo_data:
        return ""
    
    if geo_data.get("status") == "private":
        return "  [GeoIP] Local / Private Network Target"

    if geo_data.get("status") != "success":
        return f"  [GeoIP] Lookup failed: {geo_data.get('message', 'Unknown error')}"

    lines = [
        "  ┌── Geolocation & WAN Intelligence ──────────────────────────",
        f"  │ Target IP   : {geo_data.get('query', geo_data.get('ip', ''))}",
        f"  │ Location    : {geo_data.get('city', 'Unknown')}, {geo_data.get('regionName', '')} {geo_data.get('zip', '')}, {geo_data.get('country', 'Unknown')} ({geo_data.get('countryCode', '')})",
        f"  │ Coordinates : Lat {geo_data.get('lat', 0.0)}, Lon {geo_data.get('lon', 0.0)} (TZ: {geo_data.get('timezone', 'UTC')})",
        f"  │ ISP / Org   : {geo_data.get('isp', 'Unknown')} / {geo_data.get('org', 'Unknown')}",
        f"  │ ASN         : {geo_data.get('as', 'Unknown')}",
        "  └────────────────────────────────────────────────────────────"
    ]
    return "\n".join(lines)
