"""
drive_uploader.py  — Cloud deployment version
===============================================
Uses Google Service Account (stored in Streamlit Secrets) instead of
OAuth2 browser flow. Uploads ONLY to the shared 'Safe_Cloud_Uploads' folder.

Setup (one-time):
  1. Go to Google Cloud Console → IAM & Admin → Service Accounts
  2. Create Service Account → Grant role: "Editor" or "Drive File Creator"
  3. Keys tab → Add Key → JSON → download the file
  4. In Google Drive, share the 'Safe_Cloud_Uploads' folder with the service account email
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

  # Add this too — get it from the URL when you open the folder in Drive:
  # https://drive.google.com/drive/folders/THIS_PART_IS_THE_ID
  [drive]
  upload_folder_id = "your-safe-cloud-uploads-folder-id"
"""

import os


def _get_folder_id() -> str | None:
    """Get the target Drive folder ID from Streamlit Secrets."""
    try:
        import streamlit as st
        folder_id = st.secrets.get("drive", {}).get("upload_folder_id", None)
        return folder_id if folder_id else None
    except Exception:
        return None


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

    # ── Target the shared folder if configured ────────────────────────────
    folder_id = _get_folder_id()
    file_metadata = {"name": os.path.basename(file_path)}
    if folder_id:
        file_metadata["parents"] = [folder_id]

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

    folder_id = _get_folder_id()
    file_metadata = {"name": os.path.basename(file_path)}
    if folder_id:
        file_metadata["parents"] = [folder_id]

    media = MediaFileUpload(file_path, resumable=True)

    file_resource = (
        service.files()
        .create(body=file_metadata, media_body=media, fields="id,name,webViewLink")
        .execute()
    )
    return file_resource


def upload_to_drive(file_path: str) -> dict:
    """
    Upload file to Google Drive → Safe_Cloud_Uploads folder.
    Uses Service Account if running on cloud (Streamlit Secrets available).
    Falls back to OAuth2 for local development.
    """
    try:
        import streamlit as st
        if "gcp_service_account" in st.secrets:
            return _upload_with_service_account(file_path)
    except Exception as e:
        # Re-raise with a clear message so the user sees it in the UI
        raise RuntimeError(
            f"Service Account upload failed: {e}\n\n"
            "Make sure [gcp_service_account] is set in Streamlit Secrets and the "
            "'Safe_Cloud_Uploads' folder is shared with the service account email."
        )

    # Local development fallback
    return _upload_with_oauth(file_path)