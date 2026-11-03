"""DRF permission classes backed by the RBAC matrix in ``apps.accounts.rbac``."""

from rest_framework.permissions import SAFE_METHODS, BasePermission

from . import rbac
from .rbac import Role

ROLE_ADMIN = Role.ADMIN.value
ASSIGNABLE_ROLES = tuple(role.value for role in Role)


def is_admin_user(user):
    return rbac.role_of(user) == ROLE_ADMIN


def is_business_writer(user):
    return rbac.has_perm(user, rbac.RECORDS_WRITE)


def set_user_role(user, role):
    if role not in ASSIGNABLE_ROLES:
        raise ValueError(f"Unknown role: {role}")
    user.role = role
    user.save(update_fields=["role"])


class RequirePermission(BasePermission):
    """``RequirePermission.of("audit.view")`` -> permission class for all methods."""

    permission = None

    @classmethod
    def of(cls, permission):
        return type(f"Require_{permission.replace('.', '_')}", (cls,), {"permission": permission})

    def has_permission(self, request, view):
        return rbac.has_perm(request.user, self.permission)


class ReadOrPermission(BasePermission):
    """Any authenticated user may read; writes need ``write_permission``; deletes need records.delete."""

    write_permission = rbac.RECORDS_WRITE

    @classmethod
    def of(cls, permission):
        return type(f"ReadOr_{permission.replace('.', '_')}", (cls,), {"write_permission": permission})

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False
        if request.method in SAFE_METHODS:
            return rbac.has_perm(user, rbac.RECORDS_VIEW)
        if request.method == "DELETE":
            return rbac.has_perm(user, rbac.RECORDS_DELETE)
        return rbac.has_perm(user, self.write_permission)


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return is_admin_user(request.user)


class IsBusinessWriterOrReadOnly(ReadOrPermission):
    """Kept for existing views: read for everyone, write for analyst roles, delete for managers."""
