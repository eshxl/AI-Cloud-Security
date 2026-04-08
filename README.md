# AI-Based Sensitive Data Detection and Prevention System for Cloud Uploads

A zero-tolerance AI-powered data leakage prevention system that scans documents
before cloud upload and blocks any file containing sensitive or confidential information.

---

## Features
- **27 regex patterns** covering structured PII, financial identifiers, credentials, and technical secrets
- **Gradient Boosting ML classifier** (94.9% F1) for contextual sensitivity detection
- **Zero-tolerance policy** — only SAFE files reach Google Drive
- **Supports TXT, PDF, DOCX** with real-time scanning
- **Streamlit web interface** with model performance dashboard

## Detection Categories
| Category | Types Detected |
|---|---|
| Identity | Email, Phone, Aadhaar, PAN, Passport, Voter ID, Driving Licence, DOB |
| Financial | Bank Account, IFSC, Credit Card, CVV, UPI, SWIFT/BIC, GST, Salary |
| Credentials | Password, API Key, JWT Token, AWS Key, SSH Key, Private Key, Bearer Token |
| Other PII | IP Address, Employee ID, OTP, Insurance Policy Number |

## ML Model Performance (5-Fold Cross-Validation, 122 unique samples)
| Model | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|
| **Gradient Boosting** | **95.1%** | **96.6%** | **93.3%** | **94.9%** |
| Linear SVM | 91.0% | 88.9% | 93.3% | 91.1% |
| Logistic Regression | 90.2% | 90.0% | 90.0% | 90.0% |
| Random Forest | 82.8% | 75.3% | 96.7% | 84.7% |

---

## Project Structure
```
AI-Cloud-Security/
├── app.py                  # Streamlit web interface (zero-tolerance policy)
├── detector.py             # 27-pattern regex detection + risk scoring
├── ml_model.py             # ML training, evaluation, inference
├── utils.py                # Text extraction (TXT, PDF, DOCX)
├── drive_uploader.py       # Google Drive OAuth2 upload
├── switch_google_account.py # Switch Drive account utility
├── build_dataset.py        # Dataset generator (122 unique samples)
├── dataset/
│   └── data.csv            # Training dataset
├── model.pkl               # Trained Gradient Boosting model
├── metrics.json            # Cross-validated evaluation metrics
├── credentials.json        # Google OAuth credentials (NOT committed)
├── token.pickle            # OAuth token cache (NOT committed)
└── requirements.txt
```

## Setup Instructions

### 1. Clone and create environment
```bash
git clone https://github.com/eshxl/AI-Cloud-Security.git
cd AI-Cloud-Security
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Mac/Linux
pip install -r requirements.txt
```

### 2. Google Drive credentials
1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create project → Enable Google Drive API
3. APIs & Services → Credentials → Create OAuth 2.0 Client ID (Desktop)
4. OAuth consent screen → Set to **External** → Add your Gmail as test user
5. Download as `credentials.json` → place in project root

### 3. Train the ML model
```bash
python build_dataset.py     # generate dataset/data.csv
python ml_model.py          # train models, save model.pkl + metrics.json
```

### 4. Run
```bash
streamlit run app.py
```
On first run, a browser window opens for Google account authentication.

---