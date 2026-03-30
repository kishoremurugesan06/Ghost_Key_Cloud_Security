import pyotp

# ---------------- GENERATE OTP ----------------

def generate_otp(secret):
    totp = pyotp.TOTP(secret, interval=60)
    return totp.now()


# ---------------- VERIFY OTP ----------------

def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret, interval=60)

    # allow small delay (±1 time window)
    return totp.verify(otp, valid_window=1)