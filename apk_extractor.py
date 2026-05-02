"""APK Feature Extractor for BankShield
Extracts static features from Android APKs using androguard
"""

import os
import hashlib
import logging
from androguard.misc import AnalyzeAPK
from androguard.core.apk import APK

logger = logging.getLogger(__name__)


def extract_features(apk_path: str, top_features: list) -> tuple:
    """Extract features from APK for ML classification"""
    logger.info("Starting APK analysis...")

    a = None
    d = None
    dx = None

    # Try full analysis first
    try:
        logger.debug("androguard:AnalyzeAPK - Loading APK file...")
        a, d, dx = AnalyzeAPK(apk_path)
        logger.info("androguard:APK loaded successfully")
    except Exception as e1:
        logger.warning(f"Full analysis failed ({e1}), trying APK-only parse...")
        try:
            logger.debug("androguard:APK - Falling back to APK-only parsing")
            a = APK(apk_path)
            logger.info("androguard:APK-only parse successful")
        except Exception as e2:
            logger.error(f"Cannot parse APK: {e2}")
            raise Exception(f"Cannot parse APK: {e2}")

    # Safe extraction helper
    def safe(fn, default):
        try:
            res = fn()
            return res if res is not None else default
        except Exception:
            return default

    logger.debug("androguard:Extracting APK metadata...")
    permissions  = safe(lambda: set(a.get_permissions()), set())
    activities   = safe(lambda: a.get_activities(), [])
    services     = safe(lambda: a.get_services(), [])
    receivers    = safe(lambda: a.get_receivers(), [])
    package_name = safe(lambda: a.get_package(), "unknown")
    app_name     = safe(lambda: a.get_app_name(), "Unknown")
    min_sdk      = safe(lambda: a.get_min_sdk_version(), "?")
    target_sdk   = safe(lambda: a.get_target_sdk_version(), "?")
    logger.info(f"androguard.core.bytecodes.apk:get_permissions:45 - Found {len(permissions)} permissions")

    # Normalized permission names for matching
    norm_perms = set()
    for p in permissions:
        # Match both full name and short name (e.g., READ_SMS)
        norm_perms.add(p.upper())
        norm_perms.add(p.split('.')[-1].upper())

    # ── API calls ────────────────────────────────
    api_calls = set()
    if dx is not None:
        logger.debug("androguard.core.analysis.analysis:analyze:52 - Building call graph for API extraction...")
        try:
            method_count = 0
            call_count = 0
            for method in dx.get_methods():
                method_count += 1
                for _, call, _ in method.get_xref_to():
                    api_calls.add(f"{call.get_class_name()}->{call.get_name()}")
                    call_count += 1
            logger.info(f"androguard.core.analysis.analysis:analyze:62 - Analyzed {method_count} methods, found {len(api_calls)} unique API calls")
        except Exception as e:
            logger.debug(f"androguard.core.analysis.analysis:analyze:64 - API call extraction partial failure: {e}")

    # ── Feature vector ───────────────────────────
    logger.debug("apk_extractor:extract_features:71 - Building feature vector from top features...")
    feature_vector = {}
    matched_count = 0
    for feat in top_features:
        feat_upper = feat.upper()
        # Check if the feature (permission or API) matches
        matched = (
            feat_upper in norm_perms
            or any(feat_upper in p for p in norm_perms)
            or any(feat_upper in call.upper() for call in api_calls)
        )
        feature_vector[feat] = 1 if matched else 0
        if matched:
            matched_count += 1
    logger.info(f"apk_extractor:extract_features:84 - Feature vector complete: {matched_count}/{len(top_features)} features matched")

    # ── Metadata ─────────────────────────────────
    # Build metadata
    logger.debug("apk_extractor:Compiling metadata...")
    meta = {
        "apk_name": os.path.basename(apk_path),
        "package_name": package_name,
        "app_name": app_name or "Unknown",
        "min_sdk": str(min_sdk) if min_sdk else "?",
        "target_sdk": str(target_sdk) if target_sdk else "?",
        "permissions": sorted(list(permissions)),
        "num_permissions": len(permissions),
        "num_activities": len(activities),
        "num_services": len(services),
        "num_receivers": len(receivers),
        "file_size_kb": round(os.path.getsize(apk_path) / 1024, 1),
        "md5": _md5(apk_path),
        "active_features": sum(feature_vector.values()),
        "total_features": len(feature_vector),
        "risk_signals": _get_risk_signals(norm_perms, api_calls),
    }

    return feature_vector, meta


def _md5(path: str) -> str:
    """Calculate MD5 hash of file"""
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def _get_risk_signals(permissions: set, api_calls: set) -> list:
    """Identify high-risk permissions and API calls"""
    HIGH_RISK_PERMS = [
        'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS',
        'SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE',
        'READ_CALL_LOG', 'WRITE_CALL_LOG', 'PROCESS_OUTGOING_CALLS',
        'RECORD_AUDIO', 'READ_CONTACTS', 'WRITE_CONTACTS',
        'GET_ACCOUNTS', 'USE_CREDENTIALS', 'BIND_DEVICE_ADMIN',
        'INSTALL_PACKAGES', 'RECEIVE_BOOT_COMPLETED',
    ]
    HIGH_RISK_APIS = [
        'getDeviceId', 'getSubscriberId', 'sendTextMessage',
        'execCommand', 'DexClassLoader', 'loadClass',
    ]
    signals = []
    for p in HIGH_RISK_PERMS:
        if p in permissions:
            signals.append({'type': 'permission', 'name': p, 'severity': 'high'})
    for api in HIGH_RISK_APIS:
        if any(api.lower() in call.lower() for call in api_calls):
            signals.append({'type': 'api_call', 'name': api, 'severity': 'medium'})
    return signals[:10]