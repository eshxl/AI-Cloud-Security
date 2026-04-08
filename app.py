"""
app.py  — v4 (Zero-tolerance data leakage prevention)
=======================================================
Policy: ONLY files classified as SAFE are uploaded to Google Drive.
LOW RISK, MEDIUM RISK, and HIGH RISK are ALL blocked.
No fallback to local storage — if it contains any sensitive data, it does not go to cloud.
"""

import os, json
import pandas as pd
import streamlit as st

from utils import extract_text
from ml_model import get_keywords
from drive_uploader import upload_to_drive
from detector import detect_sensitive_data, calculate_risk, get_risk_reasons

UPLOAD_FOLDER = "uploads"
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
        st.markdown(
            f"**Evaluation:** {res['cv_folds']}-Fold CV "
            f"on {res['unique_samples']} unique samples"
        )
        st.markdown("---")

        c1, c2 = st.columns(2)
        c1.metric("Accuracy",  f"{res['accuracy']  * 100:.1f}%")
        c2.metric("F1 Score",  f"{res['f1_score']  * 100:.1f}%")
        c1.metric("Precision", f"{res['precision'] * 100:.1f}%")
        c2.metric("Recall",    f"{res['recall']    * 100:.1f}%")

        st.markdown("**Confusion Matrix:**")
        cm = res["confusion_matrix"]
        st.dataframe(
            pd.DataFrame(cm,
                index=["Actual: Safe", "Actual: Sensitive"],
                columns=["Pred: Safe", "Pred: Sensitive"]),
            use_container_width=True
        )

        st.markdown("---")
        st.markdown("**All Models Compared:**")
        rows = [
            {"Model": n,
             "Accuracy":  f"{r['accuracy']  * 100:.1f}%",
             "Precision": f"{r['precision'] * 100:.1f}%",
             "Recall":    f"{r['recall']    * 100:.1f}%",
             "F1":        f"{r['f1_score']  * 100:.1f}%"}
            for n, r in metrics["all_results"].items()
        ]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        st.info(
            "Regex detects 27 structured PII/credential types. "
            "Gradient Boosting ML provides contextual detection "
            "when no structured patterns are found.",
            icon="ℹ️"
        )
    else:
        st.warning("No metrics found. Run `python ml_model.py` first.")

# ── Main ───────────────────────────────────────────────────────────────────────
st.title("🔐 AI-Based Data Leakage Detection System")
st.markdown(
    "Upload a document to scan for sensitive or confidential content. "
    "**Only files with zero detected sensitive data are uploaded to cloud storage.**"
)

uploaded_file = st.file_uploader(
    "Upload TXT, PDF, or DOCX", type=["txt", "pdf", "docx"]
)

if uploaded_file is not None:
    file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
    st.success("File received. Running security scan...")

    if st.button("Scan File 🔍"):
        text = extract_text(file_path)

        if text == "Unsupported file format":
            st.error("Unsupported file type. Please upload TXT, PDF, or DOCX.")
            if os.path.exists(file_path):
                os.remove(file_path)
        else:
            detected = detect_sensitive_data(text)
            risk     = calculate_risk(detected, text)
            reasons  = get_risk_reasons(detected)

            # ── Detection Results ──────────────────────────────────────────
            st.subheader("🔎 Detection Results")

            # Group detections into categories for clean display
            identity_fields = ["emails","phones","aadhaar","pan","passport",
                                "voter_id","driving_licence","dob"]
            financial_fields = ["bank_account","ifsc","credit_card","cvv",
                                 "upi","swift_bic","gst_number","salary_figure"]
            credential_fields = ["passwords","api_key","jwt_token","aws_key",
                                  "ssh_key","private_key","bearer_token"]
            other_fields = ["ip_address","employee_id","otp","insurance"]

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

            def show_group(title, emoji, fields):
                st.markdown(f"**{emoji} {title}**")
                cols = st.columns(2)
                for i, f in enumerate(fields):
                    val = detected.get(f, [])
                    display = val if val else "None"
                    cols[i % 2].write(f"`{label_map[f]}:` {display}")

            tab1, tab2, tab3, tab4 = st.tabs(
                ["🪪 Identity", "💰 Financial", "🔑 Credentials", "📋 Other"]
            )
            with tab1:
                show_group("Identity & Personal", "🪪", identity_fields)
            with tab2:
                show_group("Financial", "💰", financial_fields)
            with tab3:
                show_group("Credentials & Secrets", "🔑", credential_fields)
            with tab4:
                show_group("Other PII", "📋", other_fields)

            # ── Risk Assessment ────────────────────────────────────────────
            st.subheader("⚖️ Risk Assessment")

            risk_colors = {
                "SAFE":        ("✅", "success", "SAFE — No sensitive data detected"),
                "LOW RISK":    ("⚠️", "warning", "LOW RISK — Sensitive data found"),
                "MEDIUM RISK": ("🟠", "warning", "MEDIUM RISK — Sensitive data found"),
                "HIGH RISK":   ("🚫", "error",   "HIGH RISK — Critical sensitive data found"),
            }
            icon, style, label = risk_colors[risk]

            if style == "success":
                st.success(f"{icon} {label}")
            elif style == "warning":
                st.warning(f"{icon} {label}")
            else:
                st.error(f"{icon} {label}")

            # Show what was found
            if reasons:
                st.markdown("**Detected sensitive content:**")
                for r in reasons:
                    st.markdown(f"  - {r}")

            # ── Upload decision (ZERO TOLERANCE) ──────────────────────────
            st.subheader("☁️ Cloud Upload Decision")

            if risk == "SAFE":
                # Only SAFE files go to cloud
                with st.spinner("Uploading to Google Drive..."):
                    try:
                        result = upload_to_drive(file_path)
                        st.success(
                            f"✅ File securely uploaded to Google Drive.\n\n"
                            f"**File ID:** `{result.get('id', 'N/A')}`"
                        )
                    except Exception as e:
                        st.error(f"Upload failed: {e}")
                if os.path.exists(file_path):
                    os.remove(file_path)

            else:
                # ALL non-SAFE files are blocked — no exceptions, no fallback
                if os.path.exists(file_path):
                    os.remove(file_path)

                block_messages = {
                    "LOW RISK":    "This file contains sensitive information and has been blocked from cloud upload.",
                    "MEDIUM RISK": "This file contains sensitive information and has been blocked from cloud upload.",
                    "HIGH RISK":   "This file contains critical sensitive or confidential data and has been blocked.",
                }
                st.error(
                    f"🚫 **Upload Blocked**\n\n"
                    f"{block_messages[risk]}\n\n"
                    f"The file has been deleted from the server. "
                    f"Remove or redact the sensitive content before attempting to upload."
                )

                if reasons:
                    st.warning(
                        "**To make this file safe to upload, remove:**\n" +
                        "\n".join(f"  - {r}" for r in reasons)
                    )

            # ── Sensitive Keywords ─────────────────────────────────────────
            keywords = get_keywords(text)
            if keywords:
                st.subheader("🏷️ Sensitive Keywords Detected")
                st.write(", ".join(f"`{k}`" for k in keywords))