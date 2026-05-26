"""
Cloud provider detection from outside-the-VM signals.

The IMDS endpoints (``169.254.169.254`` etc.) are link-local — only the
VM itself can talk to them. From cygor's external scanner perspective,
the ways to attribute an asset to a cloud provider are:

1. **Reverse DNS / PTR records.** Cloud providers assign public DNS names
   matching well-known patterns (``ec2-X-X-X-X.compute.amazonaws.com``,
   ``X.bc.googleusercontent.com``, ``X.cloudapp.azure.com`` etc.). nmap
   already captures the PTR record into ``host.hostnames`` so we just
   pattern-match on what we already have.

2. **TLS certificate SAN matching.** Cloud-managed services (load balancers,
   managed databases) often issue certs whose SANs encode the provider
   (``*.elb.amazonaws.com``, ``*.azurewebsites.net``).

3. **IP range matching.** AWS / Azure / GCP / DO / Linode / Hetzner all
   publish their full IP allocations. The matcher in
   ``cloud_ipranges.py`` does CIDR membership checks against a local
   cache of those files — definitive when present.

This module owns #1 and #2. The IP-range matcher lives separately so its
larger data files live in the fingerprint cache.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


# Each tuple: (regex, provider, region_extractor, notes)
_PTR_PATTERNS: List = [
    # ─── AWS ───
    # Default EC2 PTRs: ec2-1-2-3-4.compute-1.amazonaws.com or
    # ec2-1-2-3-4.us-west-2.compute.amazonaws.com (region between IP and 'compute').
    (re.compile(r"^ec2-[\d-]+\..+\.compute\.amazonaws\.com$|"
                r"^ec2-[\d-]+\.compute(?:-\d+)?\.amazonaws\.com$", re.IGNORECASE),
     "AWS", "compute", "EC2 instance"),
    # EC2 internal/VPC PTRs (when reverse DNS is configured for VPC)
    (re.compile(r"ip-[\d-]+\.[a-z0-9-]+\.compute\.internal$", re.IGNORECASE),
     "AWS", "compute_internal", "EC2 (VPC reverse DNS)"),
    # AWS managed services
    (re.compile(r"\.elb\.amazonaws\.com$", re.IGNORECASE),
     "AWS", "elb", "ELB / ALB / NLB"),
    (re.compile(r"\.s3\.amazonaws\.com$|\.s3-\w+-\d+\.amazonaws\.com$", re.IGNORECASE),
     "AWS", "s3", "S3 bucket"),
    (re.compile(r"\.cloudfront\.net$", re.IGNORECASE),
     "AWS", "cloudfront", "CloudFront CDN"),
    (re.compile(r"\.execute-api\.[\w-]+\.amazonaws\.com$", re.IGNORECASE),
     "AWS", "apigateway", "API Gateway"),
    (re.compile(r"\.rds\.amazonaws\.com$", re.IGNORECASE),
     "AWS", "rds", "RDS database"),
    (re.compile(r"\.redshift\.amazonaws\.com$", re.IGNORECASE),
     "AWS", "redshift", "Redshift cluster"),

    # ─── GCP ───
    # GCE: X.bc.googleusercontent.com or X.googleusercontent.com
    (re.compile(r"\.bc\.googleusercontent\.com$", re.IGNORECASE),
     "GCP", "compute", "GCE instance"),
    (re.compile(r"\.googleusercontent\.com$", re.IGNORECASE),
     "GCP", "compute", "Google Cloud (generic)"),
    # GCP load balancer
    (re.compile(r"\.googleapis\.com$", re.IGNORECASE),
     "GCP", "googleapis", "Google API endpoint"),

    # ─── Azure ───
    # Azure VMs: hostname.cloudapp.azure.com or hostname.<region>.cloudapp.azure.com
    (re.compile(r"\.cloudapp\.azure\.com$", re.IGNORECASE),
     "Azure", "compute", "Azure VM (cloudapp)"),
    (re.compile(r"\.cloudapp\.net$", re.IGNORECASE),
     "Azure", "compute_legacy", "Azure VM (legacy cloudapp.net)"),
    (re.compile(r"\.azurewebsites\.net$", re.IGNORECASE),
     "Azure", "appservice", "Azure App Service"),
    (re.compile(r"\.database\.windows\.net$", re.IGNORECASE),
     "Azure", "sqldb", "Azure SQL Database"),
    (re.compile(r"\.blob\.core\.windows\.net$|\.file\.core\.windows\.net$|\.queue\.core\.windows\.net$|\.table\.core\.windows\.net$", re.IGNORECASE),
     "Azure", "storage", "Azure Storage account"),
    (re.compile(r"\.azurefd\.net$", re.IGNORECASE),
     "Azure", "frontdoor", "Azure Front Door"),

    # ─── DigitalOcean ───
    (re.compile(r"\.droplet\.digitalocean\.com$|\.do-internal\.com$", re.IGNORECASE),
     "DigitalOcean", "droplet", "Droplet"),

    # ─── Linode / Akamai Cloud ───
    (re.compile(r"\.ip\.linodeusercontent\.com$|\.linode\.com$|\.akamaized\.net$", re.IGNORECASE),
     "Linode", "compute", "Linode instance"),

    # ─── Vultr ───
    (re.compile(r"\.vultr\.com$|\.vultrusercontent\.com$|\.choopa\.com$", re.IGNORECASE),
     "Vultr", "compute", "Vultr instance"),

    # ─── Scaleway ───
    (re.compile(r"\.scaleway\.com$|\.scw\.cloud$|\.online\.net$|\.priv\.online\.net$", re.IGNORECASE),
     "Scaleway", "compute", "Scaleway instance"),

    # ─── Tencent Cloud ───
    (re.compile(r"\.tencentcloud\.com$|\.qcloud\.com$|\.myqcloud\.com$", re.IGNORECASE),
     "Tencent", "compute", "Tencent Cloud instance"),

    # ─── OVH ───
    (re.compile(r"\.ovh\.net$|\.ovh\.ca$|\.ovhcloud\.com$|\.your-server\.de$", re.IGNORECASE),
     "OVH", "compute", "OVH server"),

    # ─── Oracle Cloud ───
    (re.compile(r"\.oraclecloud\.com$|\.oraclevcn\.com$", re.IGNORECASE),
     "Oracle Cloud", "compute", "OCI instance"),

    # ─── Alibaba Cloud ───
    (re.compile(r"\.aliyuncs\.com$|\.alibabacloud\.com$", re.IGNORECASE),
     "Alibaba Cloud", "compute", "ECS instance"),

    # ─── Hetzner ───
    (re.compile(r"\.your-server\.de$|\.hetzner\.com$", re.IGNORECASE),
     "Hetzner", "compute", "Hetzner server"),

    # ─── IBM Cloud ───
    (re.compile(r"\.softlayer\.com$|\.cloud\.ibm$|\.us-south\.containers\.cloud\.ibm$", re.IGNORECASE),
     "IBM Cloud", "compute", "IBM Cloud / SoftLayer"),

    # ─── Cloudflare ───
    (re.compile(r"\.cloudflare\.com$|\.workers\.dev$|\.r2\.cloudflarestorage\.com$", re.IGNORECASE),
     "Cloudflare", "edge", "Cloudflare edge"),

    # ─── Fastly / Akamai (CDN) ───
    (re.compile(r"\.fastly\.net$|\.fastlylb\.net$", re.IGNORECASE),
     "Fastly", "cdn", "Fastly CDN"),
    (re.compile(r"\.akamaitechnologies\.com$|\.akamaiedge\.net$", re.IGNORECASE),
     "Akamai", "cdn", "Akamai CDN"),
]


# TLS SAN patterns reuse the same regex set — managed cloud services
# typically bake the provider hostname into the SAN list.
_TLS_SAN_PATTERNS = _PTR_PATTERNS  # same regexes; different fact source


@dataclass
class CloudDetection:
    """Result of cloud-provider attribution from a single signal."""
    provider: str          # "AWS", "GCP", "Azure", ...
    service: str           # "compute", "elb", "s3", ...
    description: str       # one-line for the audit log
    matched_value: str     # the PTR / SAN that matched
    source: str            # "ptr" or "tls_san"


def detect_from_hostname(hostname: Optional[str]) -> Optional[CloudDetection]:
    """
    Match a single hostname (typically a PTR record) against the cloud
    pattern set. Returns the first match — patterns are ordered with
    most-specific first.
    """
    if not hostname:
        return None
    for pattern, provider, service, desc in _PTR_PATTERNS:
        if pattern.search(hostname):
            return CloudDetection(
                provider=provider,
                service=service,
                description=desc,
                matched_value=hostname,
                source="ptr",
            )
    return None


def detect_from_hostnames(hostnames: List[str]) -> Optional[CloudDetection]:
    """Match against any hostname in a list — picks the first hit."""
    for h in hostnames or []:
        result = detect_from_hostname(h)
        if result:
            return result
    return None


def detect_from_tls_sans(sans: List[str]) -> List[CloudDetection]:
    """
    Match every SAN against the cloud pattern set. Returns a list because
    a single cert can carry multiple cloud-attributed names.
    """
    out: List[CloudDetection] = []
    seen: set = set()
    for san in sans or []:
        if not isinstance(san, str):
            continue
        for pattern, provider, service, desc in _TLS_SAN_PATTERNS:
            if pattern.search(san):
                key = (provider, service, san)
                if key in seen:
                    break
                seen.add(key)
                out.append(CloudDetection(
                    provider=provider,
                    service=service,
                    description=desc,
                    matched_value=san,
                    source="tls_san",
                ))
                break
    return out
