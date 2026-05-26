"""
SSH Bad Keys - Known-compromised vendor SSH private keys.

This module loads and provides access to a collection of known-compromised SSH
private keys from various vendors and products. These keys are tested automatically
against SSH targets to detect devices still using default/leaked keys.

Keys sourced from:
- Rapid7 ssh-badkeys project
- HashiCorp Vagrant insecure key
- Public CVE disclosures
"""

import yaml
import logging
from pathlib import Path
from typing import List, Dict

logger = logging.getLogger("cygor.credrecon.badkeys")

BADKEYS_DIR = Path(__file__).parent / "keys"
MANIFEST = Path(__file__).parent / "manifest.yaml"

_cache = None


def load_badkeys() -> List[Dict]:
    """Load bad key manifest with full paths resolved.

    Returns list of dicts with keys:
        file, path, vendor, product, cve, default_username, description
    """
    global _cache
    if _cache is not None:
        return _cache

    if not MANIFEST.exists():
        logger.debug("Bad keys manifest not found: %s", MANIFEST)
        _cache = []
        return _cache

    try:
        with open(MANIFEST) as f:
            data = yaml.safe_load(f)
    except Exception as e:
        logger.warning("Failed to load bad keys manifest: %s", e)
        _cache = []
        return _cache

    keys = data.get("keys", [])
    valid_keys = []
    for k in keys:
        key_path = BADKEYS_DIR / k.get("file", "")
        if key_path.exists():
            k["path"] = str(key_path)
            valid_keys.append(k)
        else:
            logger.debug("Bad key file not found: %s", key_path)

    _cache = valid_keys
    if valid_keys:
        logger.debug("Loaded %d known-compromised SSH keys", len(valid_keys))
    return _cache
