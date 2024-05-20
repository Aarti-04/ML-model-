import logging
from django.core.mail import send_mail
from django.conf import settings
from django.dispatch import receiver
from django.db.models.signals import post_save
from .models import CustomUser
from django.utils.crypto import get_random_string
from django.contrib.auth.signals import user_logged_in
logger = logging.getLogger(__name__)
@receiver(post_save, sender=CustomUser)
def send_welcome_email(sender, instance, created, **kwargs):
    print("sender",sender)
    print("instance",instance)
    if created:
        try:
            password = get_random_string(length=6)  # Customize the length as needed

            # Set the user's password
            instance.set_password(password)
            instance.save()
            subject = 'Welcome to Our Website!'
            message = f'Thank you for registering on our website. We hope you enjoy your experience! \n Your Registered password is {password}'
            from_email = settings.EMAIL_HOST_USER
            to_email = [instance.email]
            send_mail(subject, message, from_email, to_email)
            print("Email sent successfully.")
            logger.info("register Email sent successfully.")
        except Exception as e:
            print("Error sending email:", e)
            logger.error("Error sending email: %s", e)
@receiver(user_logged_in)
def send_login_email(sender, request, user, **kwargs):
    print("in signals")
    subject = 'Login Notification'
    message = f'Hi {user.name},\n\nYou have successfully logged in to spam detector application.'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [user.email]
    try:
        send_mail(subject, message, from_email, recipient_list)
        print("Login email sent successfully.")
        # logger.info("Login email sent successfully.")
    except Exception as e:
        logger.error("Error sending login email: %s", e)

