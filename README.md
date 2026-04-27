# 🛡️ BankShield: Fake Banking APK Detection

BankShield is a high-precision security tool designed to identify malicious "fake" banking applications. It uses machine learning (XGBoost) and static analysis (Androguard) to detect threats before they compromise user data.

## 🚀 Live Demo
- **Hugging Face Space**: [shubmrj/bankshield](https://huggingface.co/spaces/shubmrj/bankshield)
- **Direct App Link**: [shubmrj-bankshield.hf.space](https://shubmrj-bankshield.hf.space)

## ✨ Features
- **Instant APK Analysis**: Extract features and get a verdict in seconds.
- **ML-Powered Detection**: Uses a trained XGBoost model optimized for banking trojans.
- **Explainable AI (SHAP)**: Provides transparency by showing exactly *why* an app was flagged.
- **Static Analysis**: Parses permissions and API calls without executing the code.
- **Production-Ready UI**: Clean, modern interface with real-time scanning progress.

## 🛠️ Tech Stack
- **Backend**: Flask (Python 3.10)
- **ML Model**: XGBoost + Scikit-Learn
- **Static Analysis**: Androguard
- **Explainability**: SHAP
- **Frontend**: Modern CSS3 + Vanilla JS
- **Deployment**: Docker on Hugging Face Spaces

## 📦 Installation & Local Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/shubhmrj/Fake-Mobile-Application-Detection.git
   cd Fake-Mobile-Application-Detection
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set Environment Variables**:
   Create a `.env` file or set `HF_TOKEN` to access the model hub if models are private.
   ```bash
   export HF_TOKEN="your_huggingface_token"
   ```

4. **Run the application**:
   ```bash
   python app.py
   ```
   The app will be available at `http://localhost:7860`.

## 🧠 How it Works
1. **Upload**: The user uploads an `.apk` file.
2. **Extraction**: `androguard` extracts 241 specific features (permissions like `SEND_SMS`, API calls like `getDeviceId`).
3. **Prediction**: The feature vector is fed into the XGBoost model.
4. **Explanation**: SHAP calculates the impact of each feature on the final prediction.
5. **Verdict**: The system displays the risk level (Low, Medium, High, Critical) and key detection signals.

## 🛡️ Model Hub
The models are hosted separately on Hugging Face: [shubmrj/bankshield-models](https://huggingface.co/shubmrj/bankshield-models).

## 📄 License
This project is licensed under the MIT License.
