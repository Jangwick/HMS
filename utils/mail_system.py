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
            print(f"CRITICAL MAIL ERROR: Missing MAIL_USERNAME or MAIL_PASSWORD. Config values: USER={user is not None}, PASS={password is not None}")
            return False

        msg = EmailMessage()
        msg['Subject'] = "HMS Security Verification [MFA]"
        # Format as "Display Name <email@address.com>"
        msg['From'] = f"HMS Security Center <{sender}>"
        msg['To'] = email
        msg.set_content(f"Your HMS SuperAdmin verification code is: {otp}\n\nThis code will expire in 5 minutes.")
        
        # HTML version with improved design
        html_content = f"""
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 500px; margin: 0 auto; padding: 40px; background-color: #ffffff; border-radius: 24px; border: 1px solid #edf2f7; box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1);">
            <div style="text-align: center; margin-bottom: 32px;">
                <div style="display: inline-block; padding: 16px; background: linear-gradient(135deg, #7C3AED, #4c1d95); border-radius: 20px; box-shadow: 0 4px 12px rgba(124, 58, 237, 0.3);">
                    <span style="color: #ffffff; font-size: 32px;">🛡️</span>
                </div>
            </div>
            <h2 style="color: #1a202c; text-align: center; font-size: 26px; font-weight: 800; margin-bottom: 12px; letter-spacing: -0.025em;">Security Verification</h2>
            <p style="color: #4a5568; text-align: center; font-size: 15px; margin-bottom: 36px; line-height: 1.6;">
                A sign-in attempt was detected for the <strong>Global Command Center</strong>. Use the secure code below to verify your identity.
            </p>
            <div style="background-color: #f7fafc; padding: 32px; border-radius: 20px; text-align: center; border: 2px solid #e2e8f0; position: relative; overflow: hidden;">
                <span style="font-family: 'Courier New', Courier, monospace; font-size: 42px; font-weight: 900; letter-spacing: 12px; color: #7C3AED; position: relative; z-index: 1;">{otp}</span>
            </div>
            <p style="color: #718096; text-align: center; font-size: 13px; margin-top: 36px; line-height: 1.5;">
                This code expires in <strong>5 minutes</strong>.<br>
                If you didn't request this, please secure your account immediately.
            </p>
            <hr style="border: 0; border-top: 1px solid #edf2f7; margin: 32px 0;">
            <p style="color: #a0aec0; text-align: center; font-size: 11px; text-transform: uppercase; letter-spacing: 0.1em; font-weight: 700;">
                HMS Sentinel Security Architecture v2.4.1
            </p>
        </div>
        """
        msg.add_alternative(html_content, subtype='html')

        print(f"INFO: SMTP Handshake - {server_addr}:{port} (Auth: {user})")
        
        # Use a longer timeout for SMTP connection
        connection_timeout = 15 
        
        with smtplib.SMTP(server_addr, port, timeout=connection_timeout) as server:
            print("INFO: SMTP Connection established. Starting TLS...")
            server.starttls()
            print("INFO: TLS secure. Attempting login...")
            server.login(user, password)
            print("INFO: Login successful. Dispatching message...")
            server.send_message(msg)
            
        print(f"SUCCESS: OTP delivered to {email}")
        return True

    except smtplib.SMTPAuthenticationError:
        print("CRITICAL MAIL ERROR: Authentication failed. Please check MAIL_USERNAME and MAIL_PASSWORD (App Password).")
        return False
    except smtplib.SMTPConnectError:
        print(f"CRITICAL MAIL ERROR: Could not connect to {server_addr}:{port}. Network or firewall issue.")
        return False
    except Exception as e:
        import traceback
        print(f"CRITICAL MAIL ERROR: {str(e)}")
        print(traceback.format_exc())
        return False
