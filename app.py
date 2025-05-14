import google.generativeai as genai
import os.path
import base64
from flask import Flask, render_template
from flask import request, jsonify
from flask_cors import CORS

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import os
import json
from textblob import TextBlob
import re

#app = Flask(__name__)
app = Flask(__name__)
CORS(app)
# If modifying these SCOPES, delete the file token.json.
SCOPES = SCOPES = ["https://www.googleapis.com/auth/gmail.modify", "https://www.googleapis.com/auth/gmail.send"]


# Gemini API key
gemini_api = os.environ.get("GEMINI_API_KEY")
genai.configure(api_key=gemini_api)

# Load recipient information from JSON file

# def is_urgent_email(email):
#     """Detect if an email is urgent based on keywords."""
#     urgent_keywords = ["urgent", "asap", "immediate", "deadline", "time-sensitive"]
#     for keyword in urgent_keywords:
#         if keyword in email["body"].lower():
#             return True
#     return False

def is_urgent_email(email):
    """Detect if an email is urgent based on keywords (case-insensitive)."""
    urgent_keywords = ["urgent", "asap", "immediate", "deadline", "time-sensitive"]
    
    # Ensure body is a valid string
    email_body = email.get("body", "").lower().strip()

    # Check using regex to catch word boundaries
    for keyword in urgent_keywords:
        if re.search(rf"\b{keyword}\b", email_body, re.IGNORECASE):
            return True
    return False


def is_frustrated_sender(email):
    """Detect if the sender is frustrated or upset based on sentiment analysis."""
    blob = TextBlob(email["body"])
    sentiment = blob.sentiment.polarity
    # Negative sentiment threshold
    return sentiment < -0.3


def detect_commitments(email):
    """Detect commitments made in the email."""
    commitment_keywords = ["i will", "promise", "commit", "ensure", "follow up"]
    commitments = []
    for keyword in commitment_keywords:
        if keyword in email["body"].lower():
            commitments.append(keyword)
    return commitments

# Function to detect positive feedback
def is_positive_feedback(email):
    """Detect positive feedback or congratulatory emails."""
    positive_keywords = ["congratulations", "great job", "well done", "thank you"]
    for keyword in positive_keywords:
        if keyword in email["body"].lower():
            return True
    return False

# Function to flag and prioritize emails
def flag_and_prioritize_email(email):
    """Flag and prioritize emails based on urgency, sentiment, and commitments."""
    flags = []
    print(f"\nEmail ID: {email['id']}")
    print(f"Extracted Email Body:\n{email['body']}\n")
    if is_urgent_email(email):
        flags.append("URGENT")
    if is_frustrated_sender(email):
        flags.append("FRUSTRATED SENDER")
    commitments = detect_commitments(email)
    if commitments:
        flags.append(f"COMMITMENTS: {', '.join(commitments)}")
    if is_positive_feedback(email):
        flags.append("POSITIVE FEEDBACK")
    print(f"Flags Detected: {flags}")
    return flags

def load_recipients():
    """Load recipient information from recipients.json."""
    with open("recipients.json", "r") as file:
        return json.load(file)

# Ensure folders exist based on recipient information
def ensure_folders_exist(recipients):
    """Ensure folders exist for each recipient."""
    for folder_name in recipients.keys():
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)

# Check if an email belongs to a specific recipient
def get_email_folder(email, recipients):
    """Determine which folder an email belongs to based on the recipient."""
    for folder_name, domains in recipients.items():
        for domain in domains:
            if domain in email["from"].lower():
                return folder_name
    return None

# Save email to the appropriate folder
def save_email_to_folder(email, folder_name):
    """Save the email content to a file in the specified folder."""
    filename = f"{folder_name}/email_{email['id']}.txt"
    with open(filename, "w", encoding="utf-8") as file:
        file.write(f"From: {email['from']}\n")
        file.write(f"Subject: {email['subject']}\n")
        file.write(f"Body:\n{email['body']}\n")

# Authenticate with Gmail API
def authenticate_gmail():
    """Authenticate with Gmail API using OAuth 2.0."""
    creds = None
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        with open("token.json", "w") as token:
            token.write(creds.to_json())
    return creds

# Fetch emails from Gmail
def fetch_emails(service, max_results=10):
    """Fetch emails from the user's Gmail inbox."""
    results = service.users().messages().list(userId="me", maxResults=max_results).execute()
    messages = results.get("messages", [])
    emails = []
    recipients = load_recipients()
    ensure_folders_exist(recipients)

    for message in messages:
        msg = service.users().messages().get(userId="me", id=message["id"]).execute()
        email_data = {
    "id": msg["id"],
    "subject": next((header["value"] for header in msg["payload"]["headers"] if header["name"] == "Subject"), "No Subject"),
    "from": next((header["value"] for header in msg["payload"]["headers"] if header["name"] == "From"), "Unknown Sender"),
    "snippet": msg.get("snippet", ""),
    "body": get_email_body(msg["payload"]),
}
        # Flag and prioritize the email
        email_data["flags"] = flag_and_prioritize_email(email_data)
        emails.append(email_data)

        # Save email to the appropriate folder
        folder_name = get_email_folder(email_data, recipients)
        if folder_name:
            save_email_to_folder(email_data, folder_name)

    return emails

# Extract email body from payload
def get_email_body(payload):
    """Extract the email body from the payload."""
    if "parts" in payload:
        for part in payload["parts"]:
            if part["mimeType"] == "text/plain":
                return base64.urlsafe_b64decode(part["body"]["data"]).decode("utf-8")
    return base64.urlsafe_b64decode(payload["body"]["data"]).decode("utf-8")

# Summarize email content using Gemini
def summarize_email(text):
    """Summarize email content using Gemini."""
    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(f"Summarize the following email in 2-3 sentences:\n\n{text}")
    return response.text

# Render the front-end with summarized emails
# @app.route("/")
# def index():
#     """Render the front-end with summarized emails."""
#     # Authenticate and create the Gmail API service
#     creds = authenticate_gmail()
#     service = build("gmail", "v1", credentials=creds)

#     # Fetch emails
#     emails = fetch_emails(service, max_results=15)

#     # Summarize emails
#     summarized_emails = []
#     for email in emails:
#         summary = summarize_email(email["body"])
#         summarized_emails.append({
#             "from": email["from"],
#             "subject": email["subject"],
#             "summary": summary,
#         })

#     # Render the template with summarized emails
#     return render_template("index.html", emails=summarized_emails)

@app.route("/")
def index():
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)

    emails = fetch_emails(service, max_results=15)

    categorized_emails = {
        "Urgent": [],
        "Frustrated Sender": [],
        "Commitments": [],
        "Positive Feedback": [],
        "Normal": []
    }

    for email in emails:
        summary = summarize_email(email["body"])
        email_info = {
            "from": email["from"],
            "subject": email["subject"],
            "summary": summary,
            "flags": email["flags"]
        }

        if "URGENT" in email["flags"]:
            categorized_emails["Urgent"].append(email_info)
        elif "FRUSTRATED SENDER" in email["flags"]:
            categorized_emails["Frustrated Sender"].append(email_info)
        elif any(flag.startswith("COMMITMENTS") for flag in email["flags"]):
            categorized_emails["Commitments"].append(email_info)
        elif "POSITIVE FEEDBACK" in email["flags"]:
            categorized_emails["Positive Feedback"].append(email_info)
        else:
            categorized_emails["Normal"].append(email_info)

    return render_template("index.html", categorized_emails=categorized_emails)

# @app.route("/generate_reply", methods=["POST"])
# def generate_reply():
#     """Generate a smart AI reply for an urgent email."""
#     email_body = request.form.get("body")
#     email_from = request.form.get("from")
#     email_subject = request.form.get("subject")

#     prompt = f"""
# You are a professional email assistant. 
# Write a polite, respectful, and to-the-point reply for the following email.

# Original Sender: {email_from}
# Subject: {email_subject}
# Email Body:
# {email_body}

# Reply:
#     """

#     model = genai.GenerativeModel("gemini-1.5-flash")
#     response = model.generate_content(prompt)
#     reply_text = response.text.strip()

#     return jsonify({"reply": reply_text})


@app.route("/generate_reply", methods=["POST"])
def generate_reply():
    email_body = request.form.get("body")
    email_from = request.form.get("from")
    email_subject = request.form.get("subject")

    prompt = f"""
You are a professional email assistant. 
Write a polite, respectful, and to-the-point reply for the following email.

Original Sender: {email_from}
Subject: {email_subject}
Email Body:
{email_body}

Reply:
    """

    model = genai.GenerativeModel("gemini-1.5-flash")
    response = model.generate_content(prompt)
    reply_text = response.text.strip()

    return jsonify({
        "reply": reply_text,
        "to": email_from,
        "subject": email_subject
    })

@app.route("/send_reply", methods=["POST"])
def send_reply():
    to_email = request.form.get("to")
    subject = request.form.get("subject")
    message_body = request.form.get("body")

    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)

    from email.mime.text import MIMEText
    import base64

    message = MIMEText(message_body)
    message["to"] = to_email
    message["subject"] = "Re: " + subject

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    send_message = {"raw": raw_message}

    try:
        service.users().messages().send(userId="me", body=send_message).execute()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    

@app.route("/emails", methods=["GET"])
def get_emails():
    """API to get categorized emails."""
    creds = authenticate_gmail()
    service = build("gmail", "v1", credentials=creds)

    emails = fetch_emails(service, max_results=20)

    categorized_emails = {
        "Urgent": [],
        "Frustrated Sender": [],
        "Commitments": [],
        "Positive Feedback": [],
        "Normal": []
    }

    for email in emails:
        summary = summarize_email(email["body"])
        email_info = {
            "id": email["id"],
            "from": email["from"],
            "subject": email["subject"],
            "summary": summary,
            "flags": email["flags"],
            "replied": False,
            "reply_text": ""
        }

        if "URGENT" in email["flags"]:
            categorized_emails["Urgent"].append(email_info)
        elif "FRUSTRATED SENDER" in email["flags"]:
            categorized_emails["Frustrated Sender"].append(email_info)
        elif any(flag.startswith("COMMITMENTS") for flag in email["flags"]):
            categorized_emails["Commitments"].append(email_info)
        elif "POSITIVE FEEDBACK" in email["flags"]:
            categorized_emails["Positive Feedback"].append(email_info)
        else:
            categorized_emails["Normal"].append(email_info)

    return jsonify(categorized_emails)



if __name__ == "__main__":
    app.run(debug=True)