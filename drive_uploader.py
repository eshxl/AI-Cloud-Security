import os
import streamlit as st

from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

SCOPES = ["https://www.googleapis.com/auth/drive.file"]


def authenticate():
    """
    Manual OAuth flow (works in Streamlit Cloud).
    User logs in via link and pastes code.
    """

    flow = Flow.from_client_secrets_file(
        "credentials.json",
        scopes=SCOPES,
        redirect_uri="urn:ietf:wg:oauth:2.0:oob"
    )

    auth_url, _ = flow.authorization_url(prompt="consent")

    st.subheader("🔐 Google Authentication Required")
    st.write("1. Click the link below")
    st.write("2. Login to your Google account")
    st.write("3. Copy the code and paste below")

    st.markdown(f"[👉 Click here to authenticate]({auth_url})")

    code = st.text_input("Paste authorization code here")

    if code:
        try:
            flow.fetch_token(code=code)
            return flow.credentials
        except Exception as e:
            st.error(f"Authentication failed: {e}")

    return None


def upload_to_drive(file_path):
    """
    Upload file to Google Drive after OAuth login
    """

    creds = authenticate()

    if not creds:
        st.warning("⚠️ Please complete authentication first")
        return None

    try:
        service = build("drive", "v3", credentials=creds)

        file_metadata = {
            "name": os.path.basename(file_path)
        }

        media = MediaFileUpload(file_path, resumable=True)

        file = service.files().create(
            body=file_metadata,
            media_body=media,
            fields="id, webViewLink"
        ).execute()

        return file["webViewLink"]

    except Exception as e:
        st.error(f"Upload failed: {e}")
        return None