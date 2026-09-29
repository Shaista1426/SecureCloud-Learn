from app import create_app, mail
from flask_mail import Message

app = create_app()

with app.app_context():

    msg = Message(
        subject="SecureCloud Learn - Email Test",
        recipients=["shaistasayyad1410@gmail.com"]
    )

    msg.body = """
Hello,

This is a test email from SecureCloud Learn.

If you received this email, Flask-Mail and Gmail SMTP
are configured correctly.

Regards,
SecureCloud Learn
"""

    try:

        mail.send(msg)

        print("SUCCESS: Email sent successfully.")

    except Exception as e:

        print("EMAIL ERROR:")
        print(type(e).__name__)
        print(str(e))