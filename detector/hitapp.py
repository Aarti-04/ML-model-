import requests
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import json
# get message------------------------
def get_message(service, message_id):
  """
  Retrieves the full details of a Gmail message using its ID.

  Args:
      service: Authorized Gmail service object.
      message_id: The ID of the message to retrieve.

  Returns:
      A dictionary containing the message details, or None if the message is not found.
  """
  try:
    message = service.users().messages().get(userId='me', id=message_id).execute()
    return message
  except Exception as e:
    print(f"An error occurred: {e}")
    return None
# Message body---------------------------  
def get_message_bodies(service, max_results=3):
  """
  Retrieves the bodies of a limited number of messages from the user's inbox.

  Args:
      service: Authorized Gmail service object.
      max_results: The maximum number of messages to retrieve (default: 3).

  Returns:
      A list of message bodies (or None if not found) for each message ID.
  """
  results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=max_results).execute()
  messages = results.get('messages', [])

  message_bodies = []
  for message in messages:
    message_id = message['id']
    try:
      message_details = service.users().messages().get(userId='me', id=message_id).execute()
      body = get_message_body(message_details)  # Helper function to extract body
      message_bodies.append(body)
    except Exception as e:
      print(f"Error retrieving message {message_id}: {e}")
      message_bodies.append(None)  # Append None for error cases

  return message_bodies  
def get_message_body(message_details):
  """
  Extracts the plain text body content from a message (if available).

  Args:
      message_details: A dictionary containing the full message details.

  Returns:
      The message body as a string (or None if not found).
  """
  payload = message_details.get('payload')
  if not payload:
    return None

  # Handle plain text messages
  if 'parts' not in payload:
    if 'body' in payload:
      return payload['body']['data']  # Base64 encoded, decode as needed
    else:
      return None

  # Handle messages with multiple parts (might need adjustments for specific formats)
  parts = payload.get('parts', [])
  for part in parts:
    if part['mimeType'] == 'text/plain':
      return part['body']['data']  # Base64 encoded, decode as needed

  return None  # Body not found in parsed parts

# ====================Service build===============================  
url = "https://oauth2.googleapis.com/token"

payload = {
	"grant_type": "authorization_code",
    "client_id": "189496678458-lbsabcd97iss894bi6c5tjmnrv1e3vh8.apps.googleusercontent.com",
    "client_secret": "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",
    "redirect_uri": "http://127.0.0.1",
    "code": "4/0AeaYSHClt0jpuZA0kFHmGS4QCC7n_5CemgtDeR6M8vwVsDxq4C37u8mEObn0IKIXJSEm6Q"
}

headers = {
  'Content-Type': 'application/x-www-form-urlencoded'
}

response = requests.request("POST", url, headers=headers, data=payload)
# print(response.text)

credentials=json.loads(response.text)
# credential=response.text
# print("========credential========",credentials)
# print("===credential[access_token]====",credentials["access_token"])
credentials = Credentials(token=credentials["access_token"])
print(credentials)
gmail_service = build('gmail', 'v1', credentials=credentials)
# print(gmail_service)
message_bodies = get_message_bodies(gmail_service)

for i, body in enumerate(message_bodies):
  if body:
    print(f"Message {i+1} Body:")
    # print(body.decode('UTF-8') if body else "No body found")  # Decode from base64
  else:
    print(f"Error retrieving body for message {i+1}")
# results = gmail_service.users().messages().list(userId='me', labelIds=['INBOX'],maxResults=10).execute()
# messages = results.get('messages', [])
# if not messages:
#   print("No messages found.")
# else:
#   for message in messages:
#     message_id = message['id']
#     message_details = get_message(gmail_service, message_id)
#     print(message_details)
#     if message_details:
#       # Access various message properties within the 'message_details' dictionary
#       print(f"Message Subject: {message_details['payload']['headers'][0]['value']}")
#       # Explore other properties like 'body', 'to', 'from', etc. based on your needs
#     else:
#       print("Message not found.")
#     # print(messages)

