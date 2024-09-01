import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_email(to_email, otp):
    try:
        # SMTP setup
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.set_debuglevel(1)  # Enable debug output
        server.starttls()

        # Login
        server.login('forprojectuseemail@gmail.com', 'dykt kvbb gwzl llhw')  # Use App Password if 2-Step Verification is enabled

        # Compose the message
        msg = MIMEMultipart()
        msg['From'] = 'your-email@gmail.com'
        msg['To'] = to_email
        msg['Subject'] = 'Your OTP Code'
        body = f'Your OTP is: {otp}'
        msg.attach(MIMEText(body, 'plain'))

        # Send the email
        server.send_message(msg)
        server.quit()
        print("Email sent successfully")
    except smtplib.SMTPAuthenticationError as e:
        print(f"SMTP Authentication error: {e}")
    except smtplib.SMTPConnectError as e:
        print(f"SMTP Connect error: {e}")
    except smtplib.SMTPException as e:
        print(f"SMTP error: {e}")
    except Exception as e:
        print(f"Error sending email: {e}")


def test_send_email():
    send_email('220701169@rajalakshmi.edu.in', '123456')  # Replace with an actual recipient email and OTP


test_send_email()
