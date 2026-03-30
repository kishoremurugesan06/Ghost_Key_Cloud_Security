import smtplib
from email.mime.text import MIMEText

EMAIL = "madhavan0507p@gmail.com"
PASSWORD = "tuae zhli omyb acuj"


def send_email_otp(receiver, otp):

    subject = "GhostKey OTP Verification"

    body = f"""
GhostKey Security Verification

Your OTP is: {otp}

This OTP is valid for 60 seconds.

Do NOT share this OTP with anyone.
"""

    msg = MIMEText(body)

    msg["Subject"] = subject
    msg["From"] = EMAIL
    msg["To"] = receiver

    try:

        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)

        server.login(EMAIL, PASSWORD)

        server.sendmail(EMAIL, receiver, msg.as_string())

        server.quit()

        print("Email OTP sent successfully to:", receiver)

    except Exception as e:

        print("Email sending failed:", e)