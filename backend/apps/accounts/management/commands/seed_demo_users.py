from django.core.management.base import BaseCommand

from apps.accounts.models import User
from apps.accounts.rbac import Role

DEMO_PASSWORD = "SocDemo@2026"

DEMO_USERS = [
    ("admin", Role.ADMIN, "Veer Pratap", "Singh", "SOC Platform Administrator"),
    ("manager", Role.SOC_MANAGER, "Manish", "Bhargav", "SOC Manager"),
    ("analyst", Role.TIER1_ANALYST, "Anchal", "", "Tier-1 Security Analyst"),
    ("responder", Role.TIER2_RESPONDER, "Rudra", "", "Tier-2 Incident Responder"),
    ("auditor", Role.AUDITOR, "Vikram", "Nair", "Security Compliance Auditor"),
]


class Command(BaseCommand):
    help = "Create (or reset) one demo account per SOC role."

    def add_arguments(self, parser):
        parser.add_argument("--password", default=DEMO_PASSWORD, help=f"Password for every demo account (default {DEMO_PASSWORD}).")

    def handle(self, *args, **options):
        password = options["password"]
        rows = []
        for username, role, first, last, title in DEMO_USERS:
            user, created = User.objects.get_or_create(username=username)
            user.first_name, user.last_name, user.title = first, last, title
            user.email = f"{username}@soc.demo"
            user.role = role
            user.is_active = True
            user.auth_type = User.AuthType.LOCAL
            user.is_superuser = role == Role.ADMIN
            user.is_staff = role == Role.ADMIN
            user.set_password(password)
            user.save()
            rows.append((username, role.label, "created" if created else "reset"))
        width = max(len(r[1]) for r in rows)
        self.stdout.write(self.style.SUCCESS(f"Demo accounts (password: {password})"))
        for username, label, state in rows:
            self.stdout.write(f"  {username:<10} {label:<{width}}  {state}")
