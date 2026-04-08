"""
app.py  — Cloud deployment version (Streamlit Community Cloud)
==============================================================
Upload policy:
  SAFE      → Upload to Google Drive (Safe_Cloud_Uploads folder)
  LOW RISK  → Upload with warning (e.g. resume with just an email)
  MEDIUM    → Blocked. User must redact before uploading.
  HIGH RISK → Blocked. Critical sensitive data.
"""

import os, json
import pandas as pd
import streamlit as st

# ── Auto-train model if not present (handles fresh cloud deployment) ───────────
if not os.path.exists("model.pkl"):
    with st.spinner("First run: training ML model... (takes ~30 seconds)"):
        import subprocess
        subprocess.run(["python", "build_dataset.py"], check=True)
        subprocess.run(["python", "ml_model.py"],     check=True)

from utils import extract_text
from ml_model import get_keywords
from drive_uploader import upload_to_drive
from detector import detect_sensitive_data, calculate_risk, get_risk_reasons

# ── Use /tmp for uploads on cloud servers ─────────────────────────────────────
UPLOAD_FOLDER = "/tmp/uploads" if os.path.exists("/tmp") else "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

st.set_page_config(page_title="AI Cloud Security Scanner", page_icon="🔐", layout="wide")

# ── Sidebar: Model Performance ─────────────────────────────────────────────────
with st.sidebar:
    st.title("📊 Model Performance")
    st.caption("5-Fold Cross-Validation · 122 unique samples")

    if os.path.exists("metrics.json"):
        with open("metrics.json") as f:
            metrics = json.load(f)
        best_name = metrics["best_model"]
        res = metrics["all_results"][best_name]
        st.markdown(f"**Best Model:** `{best_name}`")
        st.markdown(f"**Evaluation:** {res['cv_folds']}-Fold CV on {res['unique_samples']} unique samples")
        st.markdown("---")
        c1, c2 = st.columns(2)
        c1.metric("Accuracy",  f"{res['accuracy']  * 100:.1f}%")
        c2.metric("F1 Score",  f"{res['f1_score']  * 100:.1f}%")
        c1.metric("Precision", f"{res['precision'] * 100:.1f}%")
        c2.metric("Recall",    f"{res['recall']    * 100:.1f}%")
        st.markdown("**Confusion Matrix:**")
        cm = res["confusion_matrix"]
        st.dataframe(pd.DataFrame(cm,
            index=["Actual: Safe","Actual: Sensitive"],
            columns=["Pred: Safe","Pred: Sensitive"]), use_container_width=True)
        st.markdown("---")
        st.markdown("**All Models Compared:**")
        rows = [{"Model":n,
                 "Accuracy":f"{r['accuracy']*100:.1f}%",
                 "Precision":f"{r['precision']*100:.1f}%",
                 "Recall":f"{r['recall']*100:.1f}%",
                 "F1":f"{r['f1_score']*100:.1f}%"}
                for n,r in metrics["all_results"].items()]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        st.info("Regex detects 27 structured PII/credential types. Gradient Boosting ML provides contextual detection.", icon="ℹ️")
    else:
        st.warning("No metrics found. Run `python ml_model.py` first.")

# ── Main ───────────────────────────────────────────────────────────────────────
st.title("🔐 AI-Based Data Leakage Detection System")
st.markdown(
    "Upload a document to scan for sensitive or confidential content. "
    "Files are uploaded to **Safe_Cloud_Uploads** on Google Drive unless critical sensitive data is detected."
)
st.info(
    "**Upload Policy:** SAFE and LOW RISK files are uploaded. "
    "MEDIUM and HIGH RISK files are blocked until sensitive data is removed.",
    icon="🛡️"
)

uploaded_file = st.file_uploader("Upload TXT, PDF, or DOCX", type=["txt","pdf","docx"])

if uploaded_file is not None:
    file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.success("File received. Running security scan...")

    if st.button("Scan File 🔍"):
        text = extract_text(file_path)

        if text == "Unsupported file format":
            st.error("Unsupported file type. Please upload TXT, PDF, or DOCX.")
            if os.path.exists(file_path): os.remove(file_path)
        else:
            detected = detect_sensitive_data(text)
            risk     = calculate_risk(detected, text)
            reasons  = get_risk_reasons(detected)

            # ── Detection Results (tabbed) ─────────────────────────────────
            st.subheader("🔎 Detection Results")
            label_map = {
                "emails":"Email","phones":"Phone","aadhaar":"Aadhaar",
                "pan":"PAN Card","passport":"Passport","voter_id":"Voter ID",
                "driving_licence":"Driving Licence","dob":"Date of Birth",
                "bank_account":"Bank Account","ifsc":"IFSC","credit_card":"Credit Card",
                "cvv":"CVV","upi":"UPI ID","swift_bic":"SWIFT/BIC",
                "gst_number":"GST Number","salary_figure":"Salary Figure",
                "passwords":"Password","api_key":"API Key","jwt_token":"JWT Token",
                "aws_key":"AWS Key","ssh_key":"SSH Key","private_key":"Private Key",
                "bearer_token":"Bearer Token","ip_address":"IP Address",
                "employee_id":"Employee ID","otp":"OTP","insurance":"Insurance Policy",
            }

            def show_group(fields):
                cols = st.columns(2)
                for i, f in enumerate(fields):
                    val = detected.get(f, [])
                    cols[i%2].write(f"`{label_map[f]}:` {val if val else 'None'}")

            tab1,tab2,tab3,tab4 = st.tabs(["🪪 Identity","💰 Financial","🔑 Credentials","📋 Other"])
            with tab1: show_group(["emails","phones","aadhaar","pan","passport","voter_id","driving_licence","dob"])
            with tab2: show_group(["bank_account","ifsc","credit_card","cvv","upi","swift_bic","gst_number","salary_figure"])
            with tab3: show_group(["passwords","api_key","jwt_token","aws_key","ssh_key","private_key","bearer_token"])
            with tab4: show_group(["ip_address","employee_id","otp","insurance"])

            # ── Risk Assessment ────────────────────────────────────────────
            st.subheader("⚖️ Risk Assessment")
            if risk == "SAFE":
                st.success("✅ SAFE — No sensitive data detected")
            elif risk == "LOW RISK":
                st.warning("⚠️ LOW RISK — Minor sensitive data found (e.g. email/phone only)")
            elif risk == "MEDIUM RISK":
                st.warning("🟠 MEDIUM RISK — Sensitive data found")
            else:
                st.error("🚫 HIGH RISK — Critical sensitive data found")

            if reasons:
                st.markdown("**Detected:**")
                for r in reasons:
                    st.markdown(f"  - {r}")

            # ── Upload Decision ────────────────────────────────────────────
            st.subheader("☁️ Cloud Upload Decision")

            # SAFE → upload normally
            if risk == "SAFE":
                with st.spinner("Uploading to Google Drive (Safe_Cloud_Uploads)..."):
                    try:
                        result = upload_to_drive(file_path)
                        link = result.get("webViewLink", "")
                        fid  = result.get("id", "N/A")
                        st.success(
                            f"✅ **Uploaded successfully** to `Safe_Cloud_Uploads`.\n\n"
                            f"File ID: `{fid}`" + (f"\n\n[Open in Drive]({link})" if link else "")
                        )
                    except Exception as e:
                        st.error(f"Upload failed: {e}")
                if os.path.exists(file_path): os.remove(file_path)

            # LOW RISK → upload with warning banner
            elif risk == "LOW RISK":
                st.warning(
                    "⚠️ **LOW RISK — Uploading with caution.**\n\n"
                    "Only minor data (e.g. email address or phone number) was found. "
                    "This is common in resumes and business documents."
                )
                with st.spinner("Uploading to Google Drive (Safe_Cloud_Uploads)..."):
                    try:
                        result = upload_to_drive(file_path)
                        link = result.get("webViewLink", "")
                        fid  = result.get("id", "N/A")
                        st.success(
                            f"✅ **Uploaded with warning** to `Safe_Cloud_Uploads`.\n\n"
                            f"File ID: `{fid}`" + (f"\n\n[Open in Drive]({link})" if link else "")
                        )
                    except Exception as e:
                        st.error(f"Upload failed: {e}")
                if os.path.exists(file_path): os.remove(file_path)

            # MEDIUM / HIGH RISK → block
            else:
                if os.path.exists(file_path): os.remove(file_path)
                st.error(
                    f"🚫 **Upload Blocked — {risk}**\n\n"
                    f"This file contains sensitive information and has been blocked from cloud upload. "
                    f"The file has been deleted from the server."
                )
                if reasons:
                    st.warning(
                        "**Please remove or redact the following before re-uploading:**\n" +
                        "\n".join(f"  - {r}" for r in reasons)
                    )

            keywords = get_keywords(text)
            if keywords:
                st.subheader("🏷️ Sensitive Keywords")
                st.write(", ".join(f"`{k}`" for k in keywords))