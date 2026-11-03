from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Send a test email to check the NEXUS-SOC alert email (SMTP) settings."

    def add_arguments(self, parser):
        parser.add_argument("--to", action="append", help="Recipient (repeatable). Default: ALERT_EMAIL_TO.")

    def handle(self, *args, **options):
        recipients = options["to"] or list(settings.ALERT_EMAIL_TO)
        if not recipients:
            raise CommandError("No recipients: set ALERT_EMAIL_TO in backend/.env or pass --to you@example.com.")
        self.stdout.write(f"Backend: {settings.EMAIL_BACKEND}")
        if settings.EMAIL_HOST:
            self.stdout.write(f"SMTP:    {settings.EMAIL_HOST}:{settings.EMAIL_PORT} as {settings.EMAIL_HOST_USER or '(no login)'}")
        try:
            send_mail(
                "[NEXUS-SOC] Test alert email",
                "If you can read this, NEXUS-SOC can send alert emails.",
                settings.DEFAULT_FROM_EMAIL,
                recipients,
                fail_silently=False,
            )
        except Exception as exc:
            raise CommandError(f"Sending failed: {type(exc).__name__}: {exc}") from exc
        self.stdout.write(self.style.SUCCESS(f"Test email sent to {', '.join(recipients)}"))
