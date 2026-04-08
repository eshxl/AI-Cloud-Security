"""
drive_uploader.py  — Cloud deployment version
===============================================
Uses Google Service Account (stored in Streamlit Secrets) instead of
OAuth2 browser flow. This works headlessly on Streamlit Community Cloud,
Render, Hugging Face Spaces, or any cloud server.

Setup (one-time):
  1. Go to Google Cloud Console → IAM & Admin → Service Accounts
  2. Create Service Account → Grant role: "Editor" or "Drive File Creator"
  3. Keys tab → Add Key → JSON → download the file
  4. In Google Drive, share the upload folder with the service account email
  5. In Streamlit Cloud → App Settings → Secrets → paste the JSON content

Streamlit Secrets format (in the cloud dashboard, under "Secrets"):
  [gcp_service_account]
  type = "service_account"
  project_id = "your-project-id"
  private_key_id = "key-id"
  private_key = "-----BEGIN RSA PRIVATE KEY-----\\n...\\n-----END RSA PRIVATE KEY-----\\n"
  client_email = "your-sa@your-project.iam.gserviceaccount.com"
  client_id = "123456789"
  auth_uri = "https://accounts.google.com/o/oauth2/auth"
  token_uri = "https://oauth2.googleapis.com/token"

LOCAL FALLBACK:
  If Streamlit Secrets are not available (local dev), falls back to
  the original OAuth2 token.pickle / credentials.json flow.
"""

import os
import json


def _upload_with_service_account(file_path: str) -> dict:
    """Upload using Service Account credentials from Streamlit Secrets."""
    import streamlit as st
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload

    # Load credentials from Streamlit Secrets
    sa_info = dict(st.secrets["gcp_service_account"])
    # Fix newlines in private key (Streamlit Secrets escapes them)
    if "\\n" in sa_info.get("private_key", ""):
        sa_info["private_key"] = sa_info["private_key"].replace("\\n", "\n")

    credentials = service_account.Credentials.from_service_account_info(
        sa_info,
        scopes=["https://www.googleapis.com/auth/drive.file"]
    )

    service = build("drive", "v3", credentials=credentials)
    file_metadata = {"name": os.path.basename(file_path)}
    media = MediaFileUpload(file_path, resumable=True)

    file_resource = (
        service.files()
        .create(body=file_metadata, media_body=media, fields="id,name,webViewLink")
        .execute()
    )
    return file_resource


def _upload_with_oauth(file_path: str) -> dict:
    """Upload using local OAuth2 token (local development only)."""
    import pickle
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload

    SCOPES = ["https://www.googleapis.com/auth/drive.file"]
    creds = None

    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            from google.auth.transport.requests import Request
            creds.refresh(Request())
        else:
            if not os.path.exists("credentials.json"):
                raise FileNotFoundError(
                    "credentials.json not found. "
                    "Download from Google Cloud Console → APIs & Services → Credentials."
                )
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)

    service = build("drive", "v3", credentials=creds)
    file_metadata = {"name": os.path.basename(file_path)}
    media = MediaFileUpload(file_path, resumable=True)

    file_resource = (
        service.files()
        .create(body=file_metadata, media_body=media, fields="id,name,webViewLink")
        .execute()
    )
    return file_resource


def upload_to_drive(file_path: str) -> dict:
    """
    Upload file to Google Drive.
    Uses Service Account if running on cloud (Streamlit Secrets available).
    Falls back to OAuth2 for local development.
    """
    try:
        import streamlit as st
        if "gcp_service_account" in st.secrets:
            return _upload_with_service_account(file_path)
    except Exception:
        pass

    # Local development fallback
    return _upload_with_oauth(file_path)