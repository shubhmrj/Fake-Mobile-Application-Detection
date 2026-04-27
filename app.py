from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import numpy as np
import shap
import os
import traceback
import tempfile

from apk_extractor import extract_features

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = None


BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = tempfile.gettempdir()


def download_models():
    
    from huggingface_hub import hf_hub_download

    HF_REPO_ID = "shubmrj/bankshield-models"

    os.makedirs("models", exist_ok=True)

    files = [
        "best_model.pkl",
        "top_features.pkl",
        "scaler.pkl",
        "label_encoder.pkl"
    ]

    for filename in files:
        dest = os.path.join("models", filename)
        if not os.path.exists(dest):
            print(f"⬇️  Downloading {filename}...")
            try:
                hf_hub_download(
                    repo_id=HF_REPO_ID,
                    filename=filename,
                    repo_type="model",
                    local_dir="models",
                    local_dir_use_symlinks=False
                )
                print(f" {filename} ready")
            except Exception as e:
                print(f" Failed to download {filename}: {e}")
        else:
            print(f" {filename} already exists")

download_models()

MODEL_PATH    = os.path.join(BASE_DIR, 'models', 'best_model.pkl')
FEATURES_PATH = os.path.join(BASE_DIR, 'models', 'top_features.pkl')
SCALER_PATH   = os.path.join(BASE_DIR, 'models', 'scaler.pkl')
LE_PATH       = os.path.join(BASE_DIR, 'models', 'label_encoder.pkl')

try:
    model         = joblib.load(MODEL_PATH)
    top_features  = joblib.load(FEATURES_PATH)
    scaler        = joblib.load(SCALER_PATH)
    label_encoder = joblib.load(LE_PATH)
    print(f"\Model loaded: {type(model).__name__}")
    print(f"   Features: {len(top_features)}")
except Exception as e:
    print(f"Model load failed: {e}")
    model = top_features = scaler = label_encoder = None




@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan_apk():
    if model is None:
        return jsonify({'success': False,
                        'error': 'Model not loaded.'}), 500

    if 'apk' not in request.files:
        return jsonify({'success': False, 'error': 'No APK file received.'}), 400

    file = request.files['apk']

    if not file.filename.lower().endswith('.apk'):
        return jsonify({'success': False, 'error': 'File must be .apk'}), 400

    tmp_path = os.path.join(UPLOAD_FOLDER, 'scan_target.apk')

    try:
        file.save(tmp_path)

        try:
            feature_vector, meta = extract_features(tmp_path, top_features)
        except ImportError as ie:
            return jsonify({'success': False, 'error': str(ie)}), 500
        except Exception as pe:
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
        except Exception:
            pass

        if confidence >= 0.85:
            risk_level, risk_color = 'CRITICAL', '#ff2d55'
        elif confidence >= 0.60:
            risk_level, risk_color = 'HIGH', '#ff6b35'
        elif confidence >= 0.40:
            risk_level, risk_color = 'MEDIUM', '#ffd60a'
        else:
            risk_level, risk_color = 'LOW', '#30d158'

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



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7860, debug=False)