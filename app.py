from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import numpy as np
import shap
import os
import traceback
import tempfile
import logging
import re
from datetime import datetime
from threading import Lock

from apk_extractor import extract_features

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = None

# ── Real-time Log Capture ────────────────────────
scan_logs = []  # Global list to store logs during scan
scan_logs_lock = Lock()
current_scan_id = None

class CaptureHandler(logging.Handler):
    """Custom handler to capture logs for streaming to frontend"""
    def __init__(self):
        super().__init__()
        self.setLevel(logging.DEBUG)

    def emit(self, record):
        global scan_logs
        # Parse log format to extract components
        msg = self.format(record)

        # Try to extract module, function, line from the message
        # Format: module.func:line - message
        match = re.match(r'(\S+?):(\S+?):(\d+)\s+-\s+(.+)', msg)
        if match:
            module, func, line, message = match.groups()
        else:
            # Fallback: use record's info
            module = record.name
            func = record.funcName
            line = str(record.lineno)
            message = record.getMessage()

        log_entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
            'level': record.levelname,
            'module': module,
            'function': func,
            'line': line,
            'message': message
        }

        with scan_logs_lock:
            scan_logs.append(log_entry)
            # Keep only last 500 logs to prevent memory bloat
            if len(scan_logs) > 500:
                scan_logs = scan_logs[-500:]

# Setup capture handler
capture_handler = CaptureHandler()
capture_handler.setFormatter(logging.Formatter('%(name)s:%(funcName)s:%(lineno)s - %(message)s'))

# Attach to androguard loggers
androguard_loggers = [
    logging.getLogger('androguard'),
    logging.getLogger('androguard.core'),
    logging.getLogger('androguard.core.analysis'),
    logging.getLogger('androguard.core.analysis.analysis'),
    logging.getLogger('androguard.core.bytecodes'),
    logging.getLogger('androguard.core.bytecodes.apk'),
    logging.getLogger('androguard.core.bytecodes.dvm'),
    logging.getLogger('apk_extractor'),
]

for logger in androguard_loggers:
    logger.addHandler(capture_handler)
    logger.setLevel(logging.DEBUG)

# Also capture our app logs
logging.getLogger().addHandler(capture_handler)

def clear_logs():
    """Clear logs at start of new scan"""
    global scan_logs, current_scan_id
    with scan_logs_lock:
        scan_logs = []
    current_scan_id = datetime.now().strftime('%Y%m%d%H%M%S')

BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = tempfile.gettempdir()


def download_models():
    import requests

    HF_TOKEN   = os.environ.get("HF_TOKEN", None)
    if HF_TOKEN:
        HF_TOKEN = HF_TOKEN.strip()
    models_dir = "/app/models"
    os.makedirs(models_dir, exist_ok=True)

    headers = {}
    if HF_TOKEN:
        headers["Authorization"] = f"Bearer {HF_TOKEN}"
        print(" HF Token loaded")
    else:
        print("  No HF_TOKEN found")

    BASE_URL = "https://huggingface.co/shubmrj/bankshield-models/resolve/main"
    files    = ["best_model.pkl", "top_features.pkl", "scaler.pkl", "label_encoder.pkl"]

    for filename in files:
        dest = os.path.join(models_dir, filename)
        url  = f"{BASE_URL}/{filename}"
        print(f"  Downloading {filename}...")
        try:
            r = requests.get(url, headers=headers, timeout=180)
            print(f"   HTTP {r.status_code}")
            if r.status_code == 200:
                with open(dest, 'wb') as f:
                    f.write(r.content)
                print(f" {filename} — {os.path.getsize(dest)} bytes")
            else:
                print(f" Failed {filename}: {r.status_code} — {r.text[:200]}")
        except Exception as e:
            print(f" Exception {filename}: {e}")

    print(f"Files in {models_dir}: {os.listdir(models_dir)}")

download_models()


MODEL_PATH    = "/app/models/best_model.pkl"
FEATURES_PATH = "/app/models/top_features.pkl"
SCALER_PATH   = "/app/models/scaler.pkl"
LE_PATH       = "/app/models/label_encoder.pkl"

try:
    model         = joblib.load(MODEL_PATH)
    top_features  = joblib.load(FEATURES_PATH)
    scaler        = joblib.load(SCALER_PATH)
    label_encoder = joblib.load(LE_PATH)
    print(f"✅ Model loaded: {type(model).__name__}")
    print(f"   Features: {len(top_features)}")
    print(f"   numpy version: {np.__version__}")
except Exception as e:
    print(f" Model load failed: {e}")
    print(f"   MODEL_PATH exists: {os.path.exists(MODEL_PATH)}")
    print(f"   numpy version: {np.__version__}")
    model = top_features = scaler = label_encoder = None



@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan_apk():
    global current_scan_id

    if model is None:
        return jsonify({'success': False,
                        'error': 'Model not loaded. Check server logs.'}), 500

    if 'apk' not in request.files:
        return jsonify({'success': False, 'error': 'No APK file received.'}), 400

    file = request.files['apk']

    if not file.filename.lower().endswith('.apk'):
        return jsonify({'success': False, 'error': 'File must be .apk'}), 400

    # Clear logs at start of scan
    clear_logs()
    logging.info(f"Starting scan for: {file.filename}")

    tmp_path = os.path.join(UPLOAD_FOLDER, 'scan_target.apk')

    try:
        file.save(tmp_path)
        print(f"APK saved: {os.path.getsize(tmp_path)} bytes")

        try:
            feature_vector, meta = extract_features(tmp_path, top_features)
            print(f"Features extracted: {sum(feature_vector.values())} active")
        except ImportError as ie:
            return jsonify({'success': False, 'error': str(ie)}), 500
        except Exception as pe:
            print(f"APK parse error: {pe}")
            traceback.print_exc()
            return jsonify({'success': False,
                            'error': f'Could not parse APK: {str(pe)}'}), 422

        row = pd.DataFrame([feature_vector])
        for feat in top_features:
            if feat not in row.columns:
                row[feat] = 0
        row = row[top_features]

        pred       = int(model.predict(row)[0])
        prob       = model.predict_proba(row)[0]
        confidence = float(prob[1])

        top_reasons = []
        try:
            from xgboost import XGBClassifier
            if isinstance(model, XGBClassifier):
                exp = shap.TreeExplainer(model)
                sv  = exp.shap_values(row)[0]
                impact = pd.Series(sv, index=top_features)
                for feat in impact.abs().nlargest(5).index:
                    top_reasons.append({
                        'feature':   feat,
                        'value':     int(row[feat].values[0]),
                        'direction': 'suspicious' if impact[feat] > 0 else 'safe',
                        'impact':    round(float(impact[feat]), 4)
                    })
        except Exception as se:
            print(f"SHAP skipped: {se}")

        if confidence >= 0.85:
            risk_level, risk_color = 'CRITICAL', '#ff2d55'
        elif confidence >= 0.60:
            risk_level, risk_color = 'HIGH', '#ff6b35'
        elif confidence >= 0.40:
            risk_level, risk_color = 'MEDIUM', '#ffd60a'
        else:
            risk_level, risk_color = 'LOW', '#30d158'

        print(f"Result: {'MALICIOUS' if pred==1 else 'LEGITIMATE'} — {confidence*100:.1f}%")

        return jsonify({
            'success':           True,
            'verdict':           'MALICIOUS' if pred == 1 else 'LEGITIMATE',
            'pred_label':        pred,
            'confidence':        round(confidence * 100, 1),
            'risk_level':        risk_level,
            'risk_color':        risk_color,
            'top_reasons':       top_reasons,
            'meta':              meta,
            'features_analyzed': len(top_features),
            'active_features':   sum(feature_vector.values()),
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500

    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


@app.route('/features', methods=['GET'])
def get_features():
    if top_features is None:
        return jsonify({'error': 'Model not loaded'}), 500
    return jsonify({'features': top_features, 'count': len(top_features)})


@app.route('/logs', methods=['GET'])
def get_logs():
    """Return captured logs for the developer console"""
    since = request.args.get('since', 0, type=int)
    with scan_logs_lock:
        # Return logs after the given index
        if since < len(scan_logs):
            return jsonify({
                'logs': scan_logs[since:],
                'total': len(scan_logs),
                'scan_id': current_scan_id
            })
        return jsonify({'logs': [], 'total': len(scan_logs), 'scan_id': current_scan_id})


@app.route('/logs/clear', methods=['POST'])
def clear_logs_endpoint():
    """Clear logs - call at start of new scan"""
    clear_logs()
    return jsonify({'success': True, 'scan_id': current_scan_id})



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7860, debug=False)