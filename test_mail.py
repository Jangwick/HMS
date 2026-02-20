import os
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage

load_dotenv()

def test_mail():
    server = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    port = int(os.environ.get('MAIL_PORT', 587))
    user = os.environ.get('MAIL_USERNAME')
    password = os.environ.get('MAIL_PASSWORD')
    
    print(f"Testing mail with: {user}")
    
    msg = EmailMessage()
    msg.set_content("This is a test from HMS.")
    msg['Subject'] = "HMS Mail Test"
    msg['From'] = user
    msg['To'] = user
    
    try:
        with smtplib.SMTP(server, port) as smtp:
            smtp.starttls()
            smtp.login(user, password)
            smtp.send_message(msg)
            print("SUCCESS: Mail sent!")
    except Exception as e:
        print(f"FAILED: {e}")

if __name__ == "__main__":
    test_mail()
