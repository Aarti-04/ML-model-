from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
import json
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64 
def gmail_credentials():
    # Set up OAuth2 credentials
    # try:
        # creds = Credentials.from_authorized_user_file('token.json')
    # except FileNotFoundError: #-- token.json file does NOT exist --#
        #-- generate token by authorizing via browser (1st time only, I hope so :D) --#
    flow = InstalledAppFlow.from_client_secrets_file(
        'credentials.json',  #credentials JSON file
        ['https://www.googleapis.com/auth/gmail.send',"https://www.googleapis.com/auth/gmail.readonly","https://mail.google.com/"]
        )
    creds = flow.run_local_server(port=8000)

    #-- token.json exists --#    
    if creds and creds.valid:
        pass

    #-- token is expired--#      
    elif creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())

    # Save the credentials as token
    with open('token.json', 'w') as token_file:
        token_file.write(creds.to_json())

    # return the creds

    return creds
def gmail_compose(mail_subject, email_recipient, mail_body):
    message = {
        'raw': base64.urlsafe_b64encode(
            f'MIME-Version: 1.0\n'
            f'Content-Type: text/html; charset="UTF-8"\n'
            f"From: itbase.tv@gmail.com\n"
            f"To: {email_recipient}\n"
            f"Subject: {mail_subject}\n\n"
            f"{mail_body}"
            .encode("utf-8")
        ).decode("utf-8")
    }
    return message

def gmail_send(creds, message):
# Send the email
    service = build('gmail', 'v1', credentials=creds)
    try:
        service.users().messages().send(userId='me', body=message).execute()
        print('Email sent successfully.')
        return True
    except Exception as e:
        print('An error occurred while sending the email:', str(e))
        return False


if __name__ == "__main__":
    creds=gmail_credentials()
    with open('token.json', 'r') as file:
        data = json.load(file)
    # mail reading................
    # try:
    #     service = build("gmail", "v1", credentials=creds)
    #     results = service.users().labels().list(userId="me").execute()
    #     labels = results.get("labels", [])
    #     if not labels:
    #         print("No labels found.")
             
    #     print("Labels:")
    #     for label in labels:
    #         print(label["name"])

    # except HttpError as error:
    #     # TODO(developer) - Handle errors from gmail API.
    #     print(f"An error occurred: {error}")
    # mail sending...............
    # mail_body="<html><h1>hello user how are you doing?</h1><br><br><h3>you have won 10 lacs case prize please go through bellow link and get complete your process</h3></html>"
    # message=gmail_compose("Demo mail from using GCP console application","sharma.aarti.dcs24@vnsgu.ac.in",mail_body)
    # mail_sent_or_not=gmail_send(creds,message)
    # print(mail_sent_or_not)
    # dummy.......
    # credentials = Credentials()
    #         # Check if the credentials is expired
    # if credentials.expired:
    #     # Refresh the token
    #     print("token got refresh")
    #     request = requests.Request()
    #     credentials.refresh(request)   
    # service = build('gmail', 'v1', credentials=credentials)
    
    # Assuming the JSON structure is like {'access_token': 'your_access_token_value'}
    # Fetch the access token
    # access_token = data
    # print(access_token)
    # user_info_url = f"https://www.googleapis.com/oauth2/v1/userinfo?access_token={access_token}"
    # user_info_response = requests.get(user_info_url)
    print(creds)