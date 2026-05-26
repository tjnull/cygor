"""
Cloud IP-range membership lookup.

AWS, Azure, GCP, DigitalOcean, Linode, OCI, and Cloudflare publish
authoritative IP-allocation files. When a scanned IP falls inside one of
those ranges, attribution is definitive (no false positives possible —
the cloud provider literally owns that block).

Cache layout (under ``~/.cache/cygor/fingerprints/``):
    cloud_aws.json          (parsed from ip-ranges.amazonaws.com)
    cloud_gcp.json          (parsed from gstatic.com/ipranges/cloud.json)
    cloud_azure.json        (parsed from Azure ServiceTags JSON)
    cloud_digitalocean.json
    cloud_linode.json
    cloud_oracle.json
    cloud_cloudflare.json

Each cache file is a flat dict:
    {
      "provider": "AWS",
      "synced_at": "2026-05-01T...",
      "prefixes": [
        {"cidr": "1.2.3.0/24", "service": "EC2", "region": "us-east-1"},
        ...
      ]
    }

Lookups are done with the ``ipaddress`` stdlib — sorted prefix arrays
make membership checks ~O(log N) per lookup, and the largest cache (AWS
~7,000 entries) loads in milliseconds.
"""
from __future__ import annotations

import ipaddress
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .cache import get_cache_dir

logger = logging.getLogger(__name__)


@dataclass
class CloudIPMatch:
    """An IP fell within a published cloud IP range."""
    provider: str         # "AWS", "GCP", "Azure", ...
    service: str          # "EC2", "S3", "ELB", "AzureFrontDoor", ...
    region: str           # "us-east-1", "europe-west2", ...
    cidr: str             # the matched CIDR


# Provider name → cache filename mapping.
_PROVIDER_FILES: Dict[str, str] = {
    "AWS":          "cloud_aws.json",
    "GCP":          "cloud_gcp.json",
    "Azure":        "cloud_azure.json",
    "DigitalOcean": "cloud_digitalocean.json",
    "Linode":       "cloud_linode.json",
    "Oracle Cloud": "cloud_oracle.json",
    "Cloudflare":   "cloud_cloudflare.json",
    "Hetzner":      "cloud_hetzner.json",
    "OVH":          "cloud_ovh.json",
    "Vultr":        "cloud_vultr.json",
    "Scaleway":     "cloud_scaleway.json",
    "Alibaba":      "cloud_alibaba.json",
    "IBM Cloud":    "cloud_ibm.json",
    "Tencent":      "cloud_tencent.json",
    "Fastly":       "cloud_fastly.json",
    "Akamai":       "cloud_akamai.json",
}


# Module-level cache so repeated lookups don't re-read JSON files.
# Each value is (parsed_v4_networks, parsed_v6_networks, raw_metadata).
_LOADED: Dict[str, Tuple[List, List, List[Dict]]] = {}


def _cache_path(provider: str) -> Path:
    return get_cache_dir() / _PROVIDER_FILES[provider]


def _load_provider(provider: str) -> Tuple[List, List, List[Dict]]:
    """
    Load and parse a provider's cache file. Returns
    ``(v4_networks, v6_networks, prefix_records)`` — the parsed
    ipaddress objects for fast membership checks plus the raw metadata
    so we can name the matched record.

    Returns three empty lists if the cache file is absent or malformed.
    Callers should treat absence as "no data, skip this provider"
    rather than an error.
    """
    if provider in _LOADED:
        return _LOADED[provider]

    path = _cache_path(provider)
    if not path.exists():
        _LOADED[provider] = ([], [], [])
        return _LOADED[provider]

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning(f"Failed to load {provider} cloud IP ranges: {e}")
        _LOADED[provider] = ([], [], [])
        return _LOADED[provider]

    prefixes = data.get("prefixes") or []
    v4: List = []
    v6: List = []
    records: List[Dict] = []
    for entry in prefixes:
        if not isinstance(entry, dict):
            continue
        cidr = entry.get("cidr") or entry.get("ip_prefix") or entry.get("ipv6_prefix")
        if not cidr:
            continue
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        record = {
            "cidr": str(net),
            "service": entry.get("service") or entry.get("system_service") or entry.get("scope") or "",
            "region": entry.get("region") or entry.get("scope") or "",
        }
        if isinstance(net, ipaddress.IPv4Network):
            v4.append((net, len(records)))
        else:
            v6.append((net, len(records)))
        records.append(record)

    # Sort by prefix length descending so the most-specific match wins.
    v4.sort(key=lambda x: x[0].prefixlen, reverse=True)
    v6.sort(key=lambda x: x[0].prefixlen, reverse=True)
    _LOADED[provider] = (v4, v6, records)
    return _LOADED[provider]


def lookup_ip(ip_str: str) -> Optional[CloudIPMatch]:
    """
    Check an IP against every loaded cloud range. Returns the first match
    found (most-specific prefix wins within a provider; provider order is
    AWS → GCP → Azure → others).

    Returns None if no provider's cache contains this IP — either it's
    not a cloud IP or the relevant cache file isn't present.
    """
    if not ip_str:
        return None
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    is_v4 = isinstance(ip, ipaddress.IPv4Address)

    for provider in _PROVIDER_FILES:
        v4, v6, records = _load_provider(provider)
        nets = v4 if is_v4 else v6
        for net, idx in nets:
            if ip in net:
                rec = records[idx]
                return CloudIPMatch(
                    provider=provider,
                    service=rec.get("service", ""),
                    region=rec.get("region", ""),
                    cidr=rec.get("cidr", ""),
                )
    return None


def clear_loaded_cache() -> None:
    """Reset the module-level cache (call after a sync refresh)."""
    _LOADED.clear()


# ---------------------------------------------------------------------------
# Cache writers — used by the sync subsystem to materialize each provider's
# IP-range data in the canonical format. Sync logic (downloading and parsing
# each provider's source URL) lives in cygor.fingerprinting.sync; this
# module owns the on-disk format.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Sync helpers — download + parse each provider's published IP-range file.
# These run synchronously via ``requests`` to keep the implementation small
# and testable. Each one returns the parsed prefix list so the caller can
# pass it to ``save_provider_ranges``.
# ---------------------------------------------------------------------------


# Canonical download URLs. AWS, GCP, and Cloudflare publish stable URLs.
# Azure publishes a download portal whose direct link rotates weekly — the
# user has to download manually, then point a local file at the parser.
_PROVIDER_URLS: Dict[str, str] = {
    "AWS":          "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "GCP":          "https://www.gstatic.com/ipranges/cloud.json",
    "Cloudflare":   "https://api.cloudflare.com/client/v4/ips",
    "DigitalOcean": "https://www.digitalocean.com/geo/google.csv",
    "Oracle Cloud": "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
    # Azure rotates the direct ServiceTags JSON URL weekly (date in filename),
    # but the download portal page is stable and embeds the latest URL in
    # plain HTML. We scrape the portal to find the current dated URL.
    "Azure":        "https://www.microsoft.com/en-us/download/details.aspx?id=56519",
    # Linode publishes RFC8805 geofeed CSV — clean, parseable, region-tagged.
    "Linode":       "https://geoip.linode.com/",
    # Providers below resolve via RIPE Stat AS lookup. The "url" here is
    # just a placeholder — the actual fetcher uses the AS list from
    # _PROVIDER_AS instead.
    "Hetzner":      "ripe-as:24940",
    "OVH":          "ripe-as:16276",
    "Vultr":        "ripe-as:20473",
    "Scaleway":     "ripe-as:12876",
    "Alibaba":      "ripe-as:37963,45102",
    "IBM Cloud":    "ripe-as:36351",
    "Tencent":      "ripe-as:132203,45090",
    "Fastly":       "ripe-as:54113",
    "Akamai":       "ripe-as:20940,63949",
}

# Map of providers that resolve via RIPE Stat AS lookup → AS number(s).
# A list lets us aggregate multi-AS providers (Alibaba and Tencent each
# operate distinct regional ASes; Akamai's CDN spans the original Akamai
# AS plus the Linode-acquired range).
_PROVIDER_AS: Dict[str, List[int]] = {
    "Hetzner":   [24940],
    "OVH":       [16276],
    "Vultr":     [20473],
    "Scaleway":  [12876],
    "Alibaba":   [37963, 45102],
    "IBM Cloud": [36351],
    "Tencent":   [132203, 45090],
    "Fastly":    [54113],
    "Akamai":    [20940, 63949],
}


# Regex that pulls the dated ServiceTags JSON URL out of the portal HTML.
# The URL has lived at this CDN GUID for years; the filename is the only
# bit that rotates (date suffix). If Microsoft restructures the portal,
# this regex misses and Azure sync raises — users fall back to --azure-file.
import re as _re
_AZURE_TAGS_URL_RE = _re.compile(
    r"https://download\.microsoft\.com/download/[a-zA-Z0-9/-]+/ServiceTags_Public_\d+\.json",
    _re.IGNORECASE,
)


def _parse_aws(data: Dict) -> List[Dict]:
    out: List[Dict] = []
    for p in data.get("prefixes", []):
        out.append({
            "cidr":    p.get("ip_prefix"),
            "service": p.get("service"),
            "region":  p.get("region"),
        })
    for p in data.get("ipv6_prefixes", []):
        out.append({
            "cidr":    p.get("ipv6_prefix"),
            "service": p.get("service"),
            "region":  p.get("region"),
        })
    return out


def _parse_gcp(data: Dict) -> List[Dict]:
    out: List[Dict] = []
    for p in data.get("prefixes", []):
        cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix")
        out.append({
            "cidr":    cidr,
            "service": p.get("service"),
            "region":  p.get("scope"),
        })
    return out


def _parse_cloudflare(data: Dict) -> List[Dict]:
    out: List[Dict] = []
    body = data.get("result", data)
    for cidr in body.get("ipv4_cidrs", []) or []:
        out.append({"cidr": cidr, "service": "edge", "region": "global"})
    for cidr in body.get("ipv6_cidrs", []) or []:
        out.append({"cidr": cidr, "service": "edge", "region": "global"})
    return out


def _parse_digitalocean_csv(text: str) -> List[Dict]:
    out: List[Dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if not parts:
            continue
        cidr = parts[0]
        region = parts[1] if len(parts) > 1 else ""
        out.append({"cidr": cidr, "service": "droplet", "region": region})
    return out


def _parse_oracle(data: Dict) -> List[Dict]:
    out: List[Dict] = []
    for region_block in data.get("regions", []):
        region = region_block.get("region")
        for cidr_obj in region_block.get("cidrs", []):
            out.append({
                "cidr":    cidr_obj.get("cidr"),
                "service": ",".join(cidr_obj.get("tags", []) or []) or "compute",
                "region":  region,
            })
    return out


def _parse_geofeed_csv(text: str, *, default_service: str = "compute") -> List[Dict]:
    """
    Parse a RFC8805 self-published geofeed CSV.

    Format per data line:  ``<ip_prefix>,<alpha2>,<region_subdiv>,<city>,<postal>``
    Lines beginning with ``#`` are comments. Used by Linode (and any other
    provider that publishes one — Hetzner does too, but their RIPE
    announced-prefixes set is more compact for cygor's purposes).
    """
    out: List[Dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if not parts or not parts[0]:
            continue
        cidr = parts[0]
        # Prefer the country+subdivision pair when present, else just country.
        country = parts[1] if len(parts) > 1 else ""
        region_subdiv = parts[2] if len(parts) > 2 else ""
        region = region_subdiv or country or "global"
        out.append({"cidr": cidr, "service": default_service, "region": region})
    return out


def _fetch_ripe_announced_prefixes(
    asns: "int | List[int]", *, timeout: int = 60
) -> List[Dict]:
    """
    Fetch every prefix announced by one or more ASes via RIPE Stat.

    RIPE Stat is a free, no-key, well-maintained source for BGP routing
    data. We use it as a fallback for cloud providers that don't publish
    their own IP-range files. Many providers operate multiple ASes
    (Alibaba 37963 + 45102, Tencent 132203 + 45090, Akamai 20940 + 63949) —
    the function accepts a list and aggregates + dedupes prefixes across
    all of them.

    The returned prefix list is parent allocations, which is the right
    granularity for "is this asset this provider?" attribution.
    """
    import requests
    if isinstance(asns, int):
        asns = [asns]
    seen: set = set()
    out: List[Dict] = []
    for asn in asns:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        try:
            resp = requests.get(
                url, timeout=timeout,
                headers={"User-Agent": "cygor-fingerprint-sync"},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.warning(f"RIPE fetch failed for AS{asn}: {e}")
            continue
        for entry in (data.get("data") or {}).get("prefixes", []) or []:
            cidr = entry.get("prefix")
            if cidr and cidr not in seen:
                seen.add(cidr)
                out.append({
                    "cidr": cidr,
                    "service": "compute",
                    "region": f"AS{asn}",
                })
    return out


def _parse_azure(data: Dict) -> List[Dict]:
    """
    Parse Azure ServiceTags JSON.

    Schema:
        {"changeNumber": ..., "cloud": "Public", "values": [
            {"name": "ActionGroup", "id": ..., "properties": {
                "changeNumber": ..., "region": "", "regionId": ...,
                "platform": "Azure", "systemService": "ActionGroup",
                "addressPrefixes": ["13.66.60.119/32", ...]
            }},
            ...
        ]}
    """
    out: List[Dict] = []
    for vt in data.get("values", []):
        if not isinstance(vt, dict):
            continue
        props = vt.get("properties") or {}
        service = props.get("systemService") or vt.get("name", "")
        region = props.get("region") or "global"
        for cidr in props.get("addressPrefixes") or []:
            out.append({"cidr": cidr, "service": service, "region": region})
    return out


def _scrape_azure_servicetags_url(timeout: int = 60) -> str:
    """
    Fetch the Azure ServiceTags download portal and extract the current
    dated JSON URL. Microsoft rotates the date in the URL weekly while
    keeping the portal page stable, so we scrape the page to find the
    latest filename.

    Raises ``RuntimeError`` if the portal HTML doesn't expose the URL —
    typically means MS restructured the page and we need to re-derive
    the regex. Users can fall back to ``--azure-file`` in that case.
    """
    try:
        import requests
    except ImportError:
        raise RuntimeError("requests is required for Azure ServiceTags scrape")

    portal_url = _PROVIDER_URLS["Azure"]
    resp = requests.get(portal_url, timeout=timeout, headers={
        "User-Agent": "Mozilla/5.0 (cygor-fingerprint-sync)",
    })
    resp.raise_for_status()
    match = _AZURE_TAGS_URL_RE.search(resp.text)
    if not match:
        raise RuntimeError(
            "Could not find ServiceTags_Public_*.json URL in the Azure download "
            "portal HTML. Microsoft may have restructured the page. "
            "Use 'cygor sync fingerprints --azure-file <path>' as a fallback."
        )
    return match.group(0)


def sync_provider(provider: str, *, timeout: int = 120) -> int:
    """
    Download and cache one provider's IP ranges. Returns the number of
    prefixes saved. Raises on network or parse failure.

    Azure is special-cased: the published JSON URL rotates weekly, so we
    scrape the stable download-portal HTML to find the current dated URL,
    then fetch and parse the resulting ServiceTags JSON. If the scrape
    misses (Microsoft restructured the portal), the user can fall back
    to ``--azure-file <path>`` for an offline import.
    """
    try:
        import requests
    except ImportError:
        raise RuntimeError("requests is required for cloud IP-range sync")

    if provider not in _PROVIDER_URLS:
        raise ValueError(f"No automatic sync URL for {provider}")

    if provider == "Azure":
        # Two-step: scrape portal → fetch JSON.
        json_url = _scrape_azure_servicetags_url(timeout=timeout)
        logger.info(f"Azure: resolved current ServiceTags URL → {json_url}")
        resp = requests.get(json_url, timeout=timeout)
        resp.raise_for_status()
        prefixes = _parse_azure(resp.json())
    elif provider in _PROVIDER_AS:
        # RIPE-by-AS providers (Hetzner, OVH).
        prefixes = _fetch_ripe_announced_prefixes(_PROVIDER_AS[provider], timeout=timeout)
    else:
        url = _PROVIDER_URLS[provider]
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()

        if provider == "AWS":
            prefixes = _parse_aws(resp.json())
        elif provider == "GCP":
            prefixes = _parse_gcp(resp.json())
        elif provider == "Cloudflare":
            prefixes = _parse_cloudflare(resp.json())
        elif provider == "DigitalOcean":
            prefixes = _parse_digitalocean_csv(resp.text)
        elif provider == "Oracle Cloud":
            prefixes = _parse_oracle(resp.json())
        elif provider == "Linode":
            prefixes = _parse_geofeed_csv(resp.text, default_service="compute")
        else:
            raise ValueError(f"No parser for {provider}")

    # Drop entries with no CIDR (parser was tolerant of missing fields).
    prefixes = [p for p in prefixes if p.get("cidr")]
    save_provider_ranges(provider, prefixes)
    return len(prefixes)


def sync_all_available(*, timeout: int = 120) -> Dict[str, int]:
    """
    Sync every provider that has an automatable URL. Failures don't stop
    the others — the function returns a dict of ``{provider: count}``
    with -1 meaning "failed".
    """
    results: Dict[str, int] = {}
    for provider in _PROVIDER_URLS:
        try:
            results[provider] = sync_provider(provider, timeout=timeout)
        except Exception as e:
            logger.warning(f"Cloud IP sync failed for {provider}: {e}")
            results[provider] = -1
    return results


def save_provider_ranges(
    provider: str,
    prefixes: List[Dict],
    *,
    synced_at: Optional[str] = None,
) -> bool:
    """
    Write a provider's IP-range list to its cache file. ``prefixes`` is a
    list of dicts each with at least ``cidr``, optionally ``service`` and
    ``region``.
    """
    if provider not in _PROVIDER_FILES:
        logger.warning(f"Unknown cloud provider: {provider}")
        return False
    from datetime import datetime
    path = _cache_path(provider)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "provider": provider,
        "synced_at": synced_at or datetime.utcnow().isoformat() + "Z",
        "count": len(prefixes),
        "prefixes": prefixes,
    }
    try:
        path.write_text(json.dumps(data), encoding="utf-8")
        # Invalidate the module-level cache so the next lookup re-reads.
        _LOADED.pop(provider, None)
        logger.info(f"Saved {len(prefixes)} {provider} IP ranges to {path}")
        return True
    except Exception as e:
        logger.error(f"Failed to save {provider} IP ranges: {e}")
        return False
