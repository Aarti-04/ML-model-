import re
from bs4 import BeautifulSoup
def is_html(message_body):
    html_pattern = re.compile(r'<[^>]+>')
    return bool(html_pattern.search(message_body))
def preprocess_email_body(body):
    if(is_html(body)):
      # print("preprocessing html bodys")  
      # body = re.sub(r'http[s]?://\S+', '', body)
      # # Remove email addresses
      # body = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '', body)
      # # Remove special characters and digits
      # body = re.sub(r'[^a-zA-Z\s]', '', body)
      # # Convert to lowercase
      # body = body.lower()
      # # print("processed body",body)
      soup = BeautifulSoup(body, "html.parser")
      body = soup.get_text(separator=" ")
    else:
       print("not html")

    # Optionally, further clean the text (e.g., remove special characters)
    body = re.sub(r'\s+', ' ', body)  # Replace multiple spaces with a single space
    body = re.sub(r'[^a-zA-Z0-9\s]', '', body)  # Remove non-alphanumeric characters
    print("Processed html bodys",body)
    # return text
    return body