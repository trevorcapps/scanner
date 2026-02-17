"""Wappalyzer integration for web technology fingerprinting.

Uses python-Wappalyzer to detect 1,270+ web technologies from HTTP responses.
Supplements our custom 103-signature fingerprint engine.
"""

import logging
import warnings

logger = logging.getLogger(__name__)

# Singleton Wappalyzer instance
_wappalyzer = None


def get_wappalyzer():
    """Get or create singleton Wappalyzer instance."""
    global _wappalyzer
    if _wappalyzer is None:
        try:
            from Wappalyzer import Wappalyzer
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                _wappalyzer = Wappalyzer.latest()
            logger.info(f"Wappalyzer loaded: {len(_wappalyzer.technologies)} technologies")
        except Exception as e:
            logger.error(f"Failed to load Wappalyzer: {e}")
    return _wappalyzer


def analyze_response(url, html, headers):
    """Analyze an HTTP response using Wappalyzer.

    Args:
        url: The URL that was fetched
        html: HTML body as string
        headers: Dict of response headers (str -> str)

    Returns:
        List of dicts: [{name, version, categories, confidence, implied}]
    """
    wap = get_wappalyzer()
    if not wap:
        return []

    try:
        from Wappalyzer import WebPage
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            webpage = WebPage(url, html or '', headers or {})
            results = wap.analyze_with_versions_and_categories(webpage)

        techs = []
        for name, info in results.items():
            versions = info.get('versions', [])
            categories = info.get('categories', [])
            version = versions[0] if versions else None

            techs.append({
                'name': name,
                'version': version,
                'categories': categories,
                'confidence': 100,  # Wappalyzer doesn't expose per-tech confidence via this API
                'source': 'wappalyzer',
            })

        logger.debug(f"Wappalyzer found {len(techs)} technologies for {url}")
        return techs

    except Exception as e:
        logger.warning(f"Wappalyzer analysis error for {url}: {e}")
        return []


def merge_with_custom(custom_matches, wap_matches):
    """Merge Wappalyzer results with our custom fingerprint matches.

    Deduplication: if both detect the same tech, prefer the one with version info.

    Args:
        custom_matches: List of our custom fingerprint match dicts
        wap_matches: List of Wappalyzer result dicts

    Returns:
        Combined list of matches
    """
    # Build lookup of custom matches by normalized name
    custom_by_name = {}
    for m in custom_matches:
        key = m.get('name', '').lower().strip()
        if key:
            custom_by_name[key] = m

    merged = list(custom_matches)

    for wm in wap_matches:
        key = wm['name'].lower().strip()
        if key in custom_by_name:
            # Duplicate — prefer version with more info
            existing = custom_by_name[key]
            if wm.get('version') and not existing.get('version'):
                # Wappalyzer has version, custom doesn't — update
                existing['version'] = wm['version']
            # Keep custom match, skip adding wap duplicate
            continue
        merged.append(wm)

    return merged
