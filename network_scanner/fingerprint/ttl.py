"""
Operating System estimation and hop count analysis based on packet Time-To-Live (TTL).
"""


def fingerprint_os_from_ttl(ttl):
    """
    Estimates the operating system family based on the initial TTL value.
    Common initial TTLs:
      - Linux / Android / macOS / iOS: 64
      - Windows: 128
      - Network devices (Cisco, routers, Solaris): 255
    Returns:
        tuple: (os_guess: str, hops: int)
    """
    if ttl is None or ttl <= 0:
        return "Unknown OS", 0

    if ttl <= 64:
        hops = 64 - ttl
        return "Linux / Unix / Apple", max(0, hops)
    elif ttl <= 128:
        hops = 128 - ttl
        return "Windows", max(0, hops)
    elif ttl <= 255:
        hops = 255 - ttl
        return "Network Device (Cisco/Solaris)", max(0, hops)
    return "Unknown OS", 0
