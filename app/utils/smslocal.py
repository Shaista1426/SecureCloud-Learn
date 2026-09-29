import os
import requests


SMSLOCAL_OTP_URL = "https://app.smslocal.in/v2/otp/send"


def send_mobile_otp(mobile_number):

    api_key = os.getenv("SMSLOCAL_API_KEY")

    if not api_key:
        raise RuntimeError(
            "SMSLOCAL_API_KEY is not configured."
        )

    response = requests.post(
        SMSLOCAL_OTP_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "to": f"+91{mobile_number}",
        },
        timeout=15,
    )

    response.raise_for_status()

    return response.json()


SMSLOCAL_OTP_VERIFY_URL = "https://app.smslocal.in/v2/otp/verify"


def verify_mobile_otp(mobile_number, otp):

    api_key = os.getenv("SMSLOCAL_API_KEY")

    if not api_key:
        raise RuntimeError(
            "SMSLOCAL_API_KEY is not configured."
        )

    response = requests.post(
        SMSLOCAL_OTP_VERIFY_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "to": f"+91{mobile_number}",
            "code": otp,
        },
        timeout=15,
    )

    response.raise_for_status()

    return response.json()