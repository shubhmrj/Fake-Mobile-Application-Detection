import os
import hashlib


def extract_features(apk_path: str, top_features: list) -> dict:
    try:
        # androguard 4.x import style
        from androguard.core.apk import APK
        from androguard.misc import AnalyzeAPK
    except ImportError:
        raise ImportError("androguard not installed. Run: pip install androguard==4.1.2")

    try:
        # androguard 4.x — AnalyzeAPK still works
        a, d, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        # Fallback: just parse APK without full analysis
        try:
            from androguard.core.apk import APK
            a = APK(apk_path)
            d = None
            dx = None
        except Exception as e2:
            raise Exception(f"Could not parse APK: {e2}")

    # ── Raw extractions ─────────────────────────────
    try:
        permissions = set(a.get_permissions())
    except Exception:
        permissions = set()

    try:
        activities = a.get_activities()
    except Exception:
        activities = []

    try:
        services = a.get_services()
    except Exception:
        services = []

    try:
        receivers = a.get_receivers()
    except Exception:
        receivers = []

    try:
        package_name = a.get_package()
    except Exception:
        package_name = "unknown"

    try:
        app_name = a.get_app_name()
    except Exception:
        app_name = "Unknown"

    try:
        min_sdk = a.get_min_sdk_version()
    except Exception:
        min_sdk = "?"

    try:
        target_sdk = a.get_target_sdk_version()
    except Exception:
        target_sdk = "?"

    # Strip android.permission. prefix for matching
    short_perms = set()
    for p in permissions:
        parts = p.split('.')
        short_perms.add(parts[-1].upper())
        short_perms.add(p.upper())

    # ── API calls (only if dx available) ────────────
    api_calls = set()
    if dx is not None:
        try:
            for method in dx.get_methods():
                for _, call, _ in method.get_xref_to():
                    class_name  = call.get_class_name()
                    method_name = call.get_name()
                    api_calls.add(f"{class_name}->{method_name}")
        except Exception:
            pass

    # ── Build feature vector ─────────────────────────
    feature_vector = {}
    for feat in top_features:
        feat_upper = feat.upper()
        matched = (
            feat_upper in short_perms
            or any(feat_upper in p for p in short_perms)
            or any(p.endswith(feat_upper) for p in short_perms)
        )
        feature_vector[feat] = 1 if matched else 0

    # ── Metadata ─────────────────────────────────────
    meta = {
        "apk_name":        os.path.basename(apk_path),
        "package_name":    package_name,
        "app_name":        app_name or "Unknown",
        "min_sdk":         min_sdk or "?",
        "target_sdk":      target_sdk or "?",
        "permissions":     sorted(list(permissions)),
        "num_permissions": len(permissions),
        "num_activities":  len(activities),
        "num_services":    len(services),
        "num_receivers":   len(receivers),
        "file_size_kb":    round(os.path.getsize(apk_path) / 1024, 1),
        "md5":             _md5(apk_path),
        "active_features": sum(feature_vector.values()),
        "total_features":  len(feature_vector),
        "risk_signals":    _get_risk_signals(short_perms, api_calls),
    }

    return feature_vector, meta


def _md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def _get_risk_signals(permissions: set, api_calls: set) -> list:
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