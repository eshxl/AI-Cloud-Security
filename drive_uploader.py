"""
drive_uploader.py
=================
Attempts to upload to Google Drive. If Drive upload fails for any reason
(quota exceeded, no credentials, no internet), falls back to saving the
file in the local cloud_storage/ folder and returns gracefully.

This fallback is appropriate for development and demo environments where
Google Drive quota may be unavailable.
"""

import os
import shutil

CLOUD_FOLDER = "cloud_storage"
os.makedirs(CLOUD_FOLDER, exist_ok=True)


def _local_fallback(file_path: str) -> str:
    """Copy file to local cloud_storage/ as a simulated cloud upload."""
    dest = os.path.join(CLOUD_FOLDER, os.path.basename(file_path))
    shutil.copy2(file_path, dest)
    return dest


def authenticate():
    """Authenticate with Google Drive API. Returns None if unavailable."""
    try:
        import pickle
        from google_auth_oauthlib.flow import InstalledAppFlow
        from google.auth.transport.requests import Request

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
                    return None
                flow = InstalledAppFlow.from_client_secrets_file(
                    "credentials.json", SCOPES
                )
                creds = flow.run_local_server(port=0)
            with open("token.pickle", "wb") as token:
                pickle.dump(creds, token)

        return creds

    except Exception:
        return None


def upload_to_drive(file_path: str) -> dict:
    """
    Upload file to Google Drive.
    Falls back to local cloud_storage/ folder if Drive is unavailable.

    Returns dict with keys:
        "method"   : "google_drive" or "local_storage"
        "location" : file ID (Drive) or local path
        "success"  : True
    """
    creds = authenticate()

    if creds is not None:
        try:
            from googleapiclient.discovery import build
            from googleapiclient.http import MediaFileUpload

            service = build("drive", "v3", credentials=creds)
            file_metadata = {"name": os.path.basename(file_path)}
            media = MediaFileUpload(file_path, resumable=True)
            result = (
                service.files()
                .create(body=file_metadata, media_body=media, fields="id")
                .execute()
            )
            file_id = result.get("id")
            print(f"Uploaded to Google Drive. File ID: {file_id}")
            return {"method": "google_drive", "location": file_id, "success": True}

        except Exception as e:
            print(f"Google Drive upload failed ({e}). Falling back to local storage.")

    # Fallback: local cloud_storage folder
    dest = _local_fallback(file_path)
    print(f"Saved to local cloud storage: {dest}")
    return {"method": "local_storage", "location": dest, "success": True}