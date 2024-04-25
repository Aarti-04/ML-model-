import os
from dotenv import load_dotenv
from email.mime.text import MIMEText
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from httplib2 import Http
import requests as customRequest
import json
import base64
# **IMPORTANT SECURITY CONSIDERATIONS:**
# 1. **Store Credentials Securely:** NEVER store your client ID, client secret, or refresh token directly in your code. These credentials should be obtained securely through a user authorization flow and stored in environment variables.
# 2. **Minimize Permissions:** Request only the Gmail API scopes that are absolutely necessary for your application. In this case, you'll likely need `https://www.googleapis.com/auth/gmail.readonly`.
# 3. **Handle Errors Gracefully:** Implement proper error handling to catch potential exceptions and provide informative messages to the user.
# 4. **Consider User Consent:** Make sure you have the user's consent to access their Gmail data before proceeding.

# Load environment variables (replace with your actual file path)
load_dotenv(".env")

def get_credentials(code =""):
    """Obtains credentials using refresh token (if available) or user authorization flow."""

    client_id = os.getenv("client_id")
    client_secret = os.getenv("client_secret")
    refresh_token = os.getenv("REFRESH_TOKEN")  # Optional

    if refresh_token:
        from google.oauth2.credentials import Credentials
        credentials = Credentials(
            token=refresh_token,
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=refresh_token,
        )
    else:
        # Implement user authorization flow
        flow = InstalledAppFlow.from_client_secrets_file(
            "credentials.json", scopes=["https://www.googleapis.com/auth/gmail.readonly"]
        )
        credentials = flow.run_local_server(port=0)
        print("<>credentials<>",credentials)

        # Save refresh token for future use (optional)
        with open(".env", "a") as f:
            f.write(f"\nREFRESH_TOKEN={credentials.refresh_token}")

    return credentials

def get_body_content(parts):
    for part in parts:
        if part["mimeType"] == "text/plain":
            data = part["body"]["data"]
            return base64.urlsafe_b64decode(data).decode()
        elif part["mimeType"] == "multipart/mixed" or "multipart/alternative":
            return get_body_content(part["parts"])
    return ""

def get_gmail_api_service(credentials):
    """Creates a Gmail API service object using the provided credentials."""

    http = credentials.authorize(Http())
    return build("gmail", "v1", http=http)

def format_headers(headers):
    """Formats email headers into a readable string."""

    formatted_headers = ""
    for header in headers:
        formatted_headers += f"{header['name']}: {header['value']}\n"
    return formatted_headers.rstrip()  # Remove trailing newline

def read_mail_with_headers(service, message_id):
    """Retrieves and parses message data, including subject, body, and formatted headers."""

    try:
        message = service.users().messages().get(userId="me", id=message_id, format="RAW").execute()
        raw_data = base64.urlsafe_b64decode(message["raw"].encode()).decode()

        # Parse the raw email data
        message_obj = MIMEText(raw_data, _charset="utf-8")

        # Extract subject and body
        subject = message_obj["Subject"]
        body = get_body_content(message_obj.walk())

        # Format and return headers
        headers = format_headers(message_obj.items())

        return subject, body, headers
    except (KeyError, HttpError) as e:
        print(f"Error retrieving message {message_id}: {e}")
        return None, None, None

def main():
    credentials = get_credentials()

    # service = get_gmail_api_service(credentials)

    # # Get a list of message IDs (adjust query as needed)
    # query = "label:inbox"  # You can set search criteria here
    # response = service.users().messages().list(userId="me", q=query).execute()
    # messages = response.get("messages", [])

    # # Process messages
    # for message in messages:
    #     message_id = message["id"]
    #     subject, body, headers = read_mail_with_headers(service, message_id)

    #     if subject and body and headers:
    #         print(f"** Message ID: {message_id} **")