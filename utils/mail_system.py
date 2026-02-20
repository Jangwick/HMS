import smtplib
from email.message import EmailMessage
from flask import current_app

def send_otp(email, otp):
    """
    Send OTP using direct smtplib (more reliable than Flask-Mail in some environments).
    """
    try:
        # Get config from current_app
        server_addr = current_app.config.get('MAIL_SERVER', 'smtp.gmail.com')
        port = current_app.config.get('MAIL_PORT', 587)
        user = current_app.config.get('MAIL_USERNAME')
        password = current_app.config.get('MAIL_PASSWORD')
        sender = current_app.config.get('MAIL_DEFAULT_SENDER') or user
        
        if not user or not password:
            print("CRITICAL MAIL ERROR: Missing MAIL_USERNAME or MAIL_PASSWORD in config.")
            return False

        msg = EmailMessage()
        msg['Subject'] = "HMS Security Verification"
        # Format as "Display Name <email@address.com>"
        msg['From'] = f"HMS Security Center <{sender}>"
        msg['To'] = email
        msg.set_content(f"Your HMS SuperAdmin verification code is: {otp}\n\nThis code will expire in 5 minutes.")
        
        # HTML version
        html_content = f"""
        <div style="font-family: 'Inter', sans-serif; max-width: 480px; margin: 0 auto; padding: 40px; background-color: #ffffff; border-radius: 20px; border: 1px solid #e2e8f0;">
            <div style="text-align: center; margin-bottom: 30px;">
                <div style="display: inline-block; padding: 12px; background: #7C3AED; border-radius: 12px;">
                    <span style="color: #ffffff; font-size: 24px;">🛡️</span>
                </div>
            </div>
            <h2 style="color: #1e293b; text-align: center; font-size: 24px; font-weight: 800; margin-bottom: 8px;">Security Check</h2>
            <p style="color: #64748b; text-align: center; font-size: 14px; margin-bottom: 30px;">Enter the code below to complete your sign-in to the Global Command Center.</p>
            <div style="background-color: #f8fafc; padding: 24px; border-radius: 16px; text-align: center; border: 2px dashed #e2e8f0;">
                <span style="font-size: 32px; font-weight: 900; letter-spacing: 8px; color: #7C3AED;">{otp}</span>
            </div>
            <p style="color: #94a3b8; text-align: center; font-size: 12px; margin-top: 30px;">
                This code expires in 5 minutes.<br>
                HMS Sentinel Security Core v2.4
            </p>
        </div>
        """
        msg.add_alternative(html_content, subtype='html')

        print(f"INFO: Attempting to send OTP to {email} via {server_addr}:{port}...")
        
        with smtplib.SMTP(server_addr, port) as server:
            server.starttls()
            server.login(user, password)
            server.send_message(msg)
            
        print(f"SUCCESS: OTP successfully delivered to {email}")
        return True

    except Exception as e:
        import traceback
        print(f"CRITICAL MAIL ERROR: {str(e)}")
        print(traceback.format_exc())
        return False
