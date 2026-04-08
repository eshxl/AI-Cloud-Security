"""
switch_google_account.py
========================
Run this to disconnect the current Google account and link a new one.

Steps:
  1. Run:  python switch_google_account.py
  2. A browser window opens → sign in with the NEW Google account
  3. Grant Drive permissions
  4. Done — all future uploads go to the new account

You can also run this any time you want to switch accounts again.
"""

import os
import pickle

TOKEN_FILE = "token.pickle"

def switch_account():
    # Step 1: Delete existing token so OAuth re-runs with new account
    if os.path.exists(TOKEN_FILE):
        os.remove(TOKEN_FILE)
        print(f"Removed existing token ({TOKEN_FILE}).")
    else:
        print("No existing token found — will authenticate fresh.")

    # Step 2: Run OAuth flow with new account
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow
        from google.auth.transport.requests import Request

        SCOPES = ["https://www.googleapis.com/auth/drive.file"]

        if not os.path.exists("credentials.json"):
            print("\nERROR: credentials.json not found in project folder.")
            print("To fix this:")
            print("  1. Go to https://console.cloud.google.com/")
            print("  2. Select your project → APIs & Services → Credentials")
            print("  3. Download OAuth 2.0 Client ID as credentials.json")
            print("  4. Place it in your project root folder")
            return

        print("\nOpening browser for Google account login...")
        print("Sign in with the NEW Google account you want to use.\n")

        flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
        creds = flow.run_local_server(port=0)

        with open(TOKEN_FILE, "wb") as token:
            pickle.dump(creds, token)

        # Show which account was linked
        print(f"\nSuccess! New Google account linked.")
        if hasattr(creds, "id_token") and creds.id_token:
            import json, base64
            payload = creds.id_token.split(".")[1]
            payload += "=" * (4 - len(payload) % 4)
            info = json.loads(base64.b64decode(payload))
            print(f"Account: {info.get('email', 'unknown')}")

        print(f"Token saved to: {TOKEN_FILE}")
        print("\nAll future uploads will go to this Google Drive account.")

    except ImportError:
        print("ERROR: Google auth libraries not installed.")
        print("Run:  pip install google-auth-oauthlib google-api-python-client")


if __name__ == "__main__":
    switch_account()