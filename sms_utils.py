from twilio.rest import Client

# Twilio credentials
account_sid = "AC2f3c44de7f91f2fc3255ccf042d85e63"
auth_token = "6f2a12ce4904852702dceb31d4acc613"

client = Client(account_sid, auth_token)


def send_sms_otp(phone, otp):

    try:

        message = client.messages.create(

            body=f"GhostKey Security OTP: {otp}",

            from_="+17407291596",   # Twilio number (no spaces)

            to=phone

        )

        print("SMS OTP sent successfully:", message.sid)

    except Exception as e:

        print("SMS sending failed:", e)