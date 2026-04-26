"""
=================================================
  apk_extractor.py
  Extracts features from a real .apk file
  using androguard — matches TUANDROMD features
=================================================
"""

import os
import re
import hashlib
from pathlib import Path


def extract_features(apk_path: str, top_features: list) -> dict:
    """
    Extract features from an APK file.
    Maps extracted data → same feature names used in TUANDROMD training.

    Args:
        apk_path:     Path to the .apk file
        top_features: List of feature names the model expects (from top_features.pkl)

    Returns:
        dict  { feature_name: 0 or 1 }
        meta  { apk_name, package_name, permissions, ... }
    """
    try:
        from androguard.misc import AnalyzeAPK
    except ImportError:
        raise ImportError(
            "androguard is not installed.\n"
            "Run: pip install androguard"
        )

    # ── Parse APK ───────────────────────────────────
    a, d, dx = AnalyzeAPK(apk_path)

    # ── Raw extractions ─────────────────────────────
    permissions   = set(a.get_permissions())           # e.g. {'android.permission.READ_SMS', ...}
    activities    = a.get_activities()
    services      = a.get_services()
    receivers     = a.get_receivers()
    providers     = a.get_providers()
    package_name  = a.get_package()
    app_name      = a.get_app_name()
    min_sdk       = a.get_min_sdk_version()
    target_sdk    = a.get_target_sdk_version()

    # Strip android.permission. prefix for matching
    short_perms = set()
    for p in permissions:
        parts = p.split('.')
        short_perms.add(parts[-1].upper())   # e.g. READ_SMS
        short_perms.add(p.upper())           # e.g. ANDROID.PERMISSION.READ_SMS

    # ── API calls from DEX ───────────────────────────
    api_calls = set()
    try:
        for method in dx.get_methods():
            for _, call, _ in method.get_xref_to():
                class_name  = call.get_class_name()
                method_name = call.get_name()
                api_calls.add(f"{class_name}->{method_name}")
    except Exception:
        pass

    # ── Build feature vector ─────────────────────────
    # TUANDROMD features are binary: permission present (1) or absent (0)
    # Feature names are typically the bare permission name (e.g. READ_SMS)

    feature_vector = {}

    for feat in top_features:
        feat_upper = feat.upper()

        # Check permission match
        matched = (
            feat_upper in short_perms
            or any(feat_upper in p for p in short_perms)
            or any(p.endswith(feat_upper) for p in short_perms)
        )
        feature_vector[feat] = 1 if matched else 0

    # ── Metadata for display ─────────────────────────
    meta = {
        "apk_name":    os.path.basename(apk_path),
        "package_name": package_name,
        "app_name":    app_name or "Unknown",
        "min_sdk":     min_sdk or "?",
        "target_sdk":  target_sdk or "?",
        "permissions": sorted(list(permissions)),
        "num_permissions": len(permissions),
        "num_activities":  len(activities),
        "num_services":    len(services),
        "num_receivers":   len(receivers),
        "file_size_kb":    round(os.path.getsize(apk_path) / 1024, 1),
        "md5": _md5(apk_path),
        "active_features": sum(feature_vector.values()),
        "total_features":  len(feature_vector),
        # Risk signals for display
        "risk_signals": _get_risk_signals(short_perms, api_calls),
    }

    return feature_vector, meta


def _md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def _get_risk_signals(permissions: set, api_calls: set) -> list:
    """Return list of high-risk signals found in the APK."""

    HIGH_RISK_PERMS = [
        'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS',
        'SYSTEM_ALERT_WINDOW', 'BIND_ACCESSIBILITY_SERVICE',
        'READ_CALL_LOG', 'WRITE_CALL_LOG', 'PROCESS_OUTGOING_CALLS',
        'RECORD_AUDIO', 'READ_CONTACTS', 'WRITE_CONTACTS',
        'GET_ACCOUNTS', 'USE_CREDENTIALS', 'BIND_DEVICE_ADMIN',
        'INSTALL_PACKAGES', 'RECEIVE_BOOT_COMPLETED',
    ]

    HIGH_RISK_APIS = [
        'getDeviceId', 'getSubscriberId', 'getLine1Number',
        'sendTextMessage', 'execCommand', 'Runtime',
        'DexClassLoader', 'loadClass', 'reflection',
        'getPassword', 'getCameraId',
    ]

    signals = []

    for p in HIGH_RISK_PERMS:
        if p in permissions:
            signals.append({'type': 'permission', 'name': p, 'severity': 'high'})

    for api in HIGH_RISK_APIS:
        if any(api.lower() in call.lower() for call in api_calls):
            signals.append({'type': 'api_call', 'name': api, 'severity': 'medium'})

    return signals[:10]  # return top 10 signals max