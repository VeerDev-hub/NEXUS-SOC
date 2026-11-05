import os
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

from botocore.config import Config
from dotenv import load_dotenv

from apps.common.logging import (
    VERBOSE_LOG_FORMAT,
)

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
CUSTOM_DIR = BASE_DIR / "custom"


def _env_int(name, default, *, minimum=1):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(minimum, value)


def _env_bool(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-secret-key-change-in-prod-32-byte-minimum")
DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true"
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",")
SOC_WEB_TIMEOUT = _env_int("SOC_WEB_TIMEOUT", 210)
SYNC_OPERATION_TIMEOUT_SECONDS = max(1, SOC_WEB_TIMEOUT - 30)
CONFIG_TEST_TIMEOUT_SECONDS = 10

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Third party
    "rest_framework",
    "rest_framework_simplejwt",
    "drf_spectacular",
    "drf_spectacular_sidecar",
    "corsheaders",
    "django_filters",
    "storages",
    "channels",
    # Local apps
    "apps.common",
    "apps.dashboard",
    "apps.settings",
    "apps.accounts",
    "apps.cases",
    "apps.alerts",
    "apps.artifacts",
    "apps.enrichments",
    "apps.playbooks",
    "apps.knowledge",
    "apps.comments",
    "apps.attachments",
    "apps.audit",
    "apps.inbox",
    "apps.preferences",
    "apps.realtime",
    "apps.webhook",
    "apps.agentic",
    "apps.agent_api",
    "apps.livedetect",
    "apps.notifications",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "soc.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "soc.wsgi.application"
ASGI_APPLICATION = "soc.asgi.application"

# Pause per offline agent step (ms) so live demos can follow the timeline; 0 disables.
AGENT_OFFLINE_STEP_DELAY_MS = _env_int("AGENT_OFFLINE_STEP_DELAY_MS", 700, minimum=0)
# ---- LLM guardrails (apps/agentic/multiagent/guardrails.py); 0 disables a limit --------
# Token budgets apply to paid providers only; local Ollama is never limited.
AGENT_RUN_TOKEN_BUDGET = _env_int("AGENT_RUN_TOKEN_BUDGET", 100_000, minimum=0)
AGENT_DAILY_TOKEN_BUDGET = _env_int("AGENT_DAILY_TOKEN_BUDGET", 1_500_000, minimum=0)
AGENT_LLM_MAX_OUTPUT_TOKENS = _env_int("AGENT_LLM_MAX_OUTPUT_TOKENS", 4096, minimum=0)
AGENT_MAX_FIELD_CHARS = _env_int("AGENT_MAX_FIELD_CHARS", 4000, minimum=200)


def _env_list(name, default=""):
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


# ---- Alert emails --------------------------------------------------------------
# Without EMAIL_HOST, emails are printed to the worker console instead of sent.
EMAIL_HOST = os.environ.get("EMAIL_HOST", "")
EMAIL_PORT = _env_int("EMAIL_PORT", 587)
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_SSL = _env_bool("EMAIL_USE_SSL", EMAIL_PORT == 465)
EMAIL_USE_TLS = _env_bool("EMAIL_USE_TLS", not EMAIL_USE_SSL)
EMAIL_TIMEOUT = _env_int("EMAIL_TIMEOUT", 20)
EMAIL_BACKEND = os.environ.get("EMAIL_BACKEND") or (
    "django.core.mail.backends.smtp.EmailBackend" if EMAIL_HOST else "django.core.mail.backends.console.EmailBackend"
)
DEFAULT_FROM_EMAIL = os.environ.get("DEFAULT_FROM_EMAIL") or (f"NEXUS-SOC <{EMAIL_HOST_USER}>" if EMAIL_HOST_USER else "NEXUS-SOC <nexus-soc@localhost>")

ALERT_EMAIL_ENABLED = _env_bool("ALERT_EMAIL_ENABLED", True)
ALERT_EMAIL_TO = _env_list("ALERT_EMAIL_TO")
ALERT_EMAIL_MIN_SEVERITY = os.environ.get("ALERT_EMAIL_MIN_SEVERITY", "High")
ALERT_EMAIL_VERDICTS = _env_list("ALERT_EMAIL_VERDICTS", "True Positive,Suspicious")
SOC_CONSOLE_URL = os.environ.get("SOC_CONSOLE_URL", "http://localhost:3000")

# Auto-mitigation: on cases at or below this severity, the Response Agent executes the
# allow-listed containment actions itself instead of waiting for a human. Actions on
# business-critical assets, and every action on higher-severity cases, still need approval.
AGENT_AUTO_MITIGATE_ENABLED = _env_bool("AGENT_AUTO_MITIGATE_ENABLED", True)
AGENT_AUTO_MITIGATE_MAX_SEVERITY = os.environ.get("AGENT_AUTO_MITIGATE_MAX_SEVERITY", "Medium")
AGENT_AUTO_MITIGATE_ACTIONS = _env_list(
    "AGENT_AUTO_MITIGATE_ACTIONS", "block_ip,block_domain,block_sender,quarantine_file,purge_email,revoke_sessions"
)

# ---- Live log detection --------------------------------------------------------
LIVE_SYSLOG_HOST = os.environ.get("LIVE_SYSLOG_HOST", "0.0.0.0")
LIVE_SYSLOG_PORT = _env_int("LIVE_SYSLOG_PORT", 5514, minimum=0)
LIVE_TAIL_FILES = _env_list("LIVE_TAIL_FILES")
LIVE_WINDOWS_EVENTLOG = os.environ.get("LIVE_WINDOWS_EVENTLOG", "auto")
LIVE_WINDOWS_CHANNELS = _env_list("LIVE_WINDOWS_CHANNELS")
LIVE_DETECTION_COOLDOWN_SECONDS = _env_int("LIVE_DETECTION_COOLDOWN_SECONDS", 600, minimum=0)

# ---- Behavioural baselines (UEBA-lite, apps/livedetect/baseline.py) -------------
UEBA_ENABLED = _env_bool("UEBA_ENABLED", True)
# A user/host profile is compared only once it has this many observations over this many hours.
UEBA_MIN_OBSERVATIONS = _env_int("UEBA_MIN_OBSERVATIONS", 10, minimum=1)
UEBA_MIN_AGE_HOURS = _env_int("UEBA_MIN_AGE_HOURS", 24, minimum=0)
UEBA_MIN_PROCESS_EVENTS = _env_int("UEBA_MIN_PROCESS_EVENTS", 200, minimum=1)
UEBA_RARE_HOUR_RATIO = float(os.environ.get("UEBA_RARE_HOUR_RATIO", "0.03"))
UEBA_MIN_ALERT_SCORE = _env_int("UEBA_MIN_ALERT_SCORE", 30, minimum=0)
UEBA_RISK_HALF_LIFE_HOURS = _env_int("UEBA_RISK_HALF_LIFE_HOURS", 24, minimum=1)
UEBA_PROCESS_ALERTS_PER_HOUR = _env_int("UEBA_PROCESS_ALERTS_PER_HOUR", 5, minimum=0)

USE_TZ = True
TIME_ZONE = os.environ.get("DJANGO_TIME_ZONE", "Asia/Kolkata")
LANGUAGE_CODE = "en-us"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("POSTGRES_DB", "soc"),
        "USER": os.environ.get("POSTGRES_USER", "postgres"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", ""),
        "HOST": os.environ.get("POSTGRES_HOST", "localhost"),
        "PORT": os.environ.get("POSTGRES_PORT", "5432"),
        "CONN_MAX_AGE": _env_int("POSTGRES_CONN_MAX_AGE", 0, minimum=0),
        "CONN_HEALTH_CHECKS": _env_bool("POSTGRES_CONN_HEALTH_CHECKS", True),
    }
}

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = os.environ.get("REDIS_PORT", "6379")
REDIS_DB = os.environ.get("REDIS_DB", "1")
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD", "")
REDIS_AUTH = f":{quote(REDIS_PASSWORD, safe='')}@" if REDIS_PASSWORD else ""
REDIS_URL = f"redis://{REDIS_AUTH}{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}"
CHANNEL_REDIS_SOCKET_TIMEOUT = int(os.environ.get("CHANNEL_REDIS_SOCKET_TIMEOUT", "10"))

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": REDIS_URL,
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        },
    }
}

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [{
                "address": REDIS_URL,
                "socket_timeout": CHANNEL_REDIS_SOCKET_TIMEOUT,
            }],
        },
    },
}

AUTH_USER_MODEL = "accounts.User"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "apps.accounts.authentication.ApiKeyAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    "DEFAULT_PAGINATION_CLASS": "apps.common.pagination.StandardResultsSetPagination",
    "PAGE_SIZE": 20,
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ],
    "DEFAULT_SCHEMA_CLASS": "apps.common.openapi.AspAutoSchema",
    "EXCEPTION_HANDLER": "apps.common.exceptions.custom_exception_handler",
}

SPECTACULAR_SETTINGS = {
    "TITLE": "NEXUS-SOC API",
    "DESCRIPTION": "HTTP API for the multi-agent NEXUS-SOC. External automation integrations should prefer API keys.",
    "VERSION": "0.5.2",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
    "SWAGGER_UI_DIST": "SIDECAR",
    "SWAGGER_UI_FAVICON_HREF": "SIDECAR",
    "REDOC_DIST": "SIDECAR",
    "SWAGGER_UI_SETTINGS": {
        "deepLinking": True,
        "persistAuthorization": True,
    },
    "POSTPROCESSING_HOOKS": [
        "drf_spectacular.hooks.postprocess_schema_enums",
        "apps.common.openapi.postprocess_business_tags",
    ],
    "TAGS": [
        {"name": "Auth", "description": "Login, refresh token, profile, and current user operations."},
        {"name": "Users", "description": "User administration APIs."},
        {"name": "API Keys", "description": "Personal API key management APIs."},
        {"name": "Cases", "description": "Case investigation records."},
        {"name": "Alerts", "description": "Security alert records."},
        {"name": "Artifacts", "description": "Indicators, assets, and other related artifacts."},
        {"name": "Enrichments", "description": "Enrichment records and creation APIs."},
        {"name": "Playbooks", "description": "Playbook records and execution APIs."},
        {"name": "Knowledge", "description": "Knowledge base records."},
        {"name": "Comments", "description": "Record comment APIs."},
        {"name": "Attachments", "description": "Attachment upload, metadata, and download APIs."},
        {"name": "Audit", "description": "Audit log query APIs."},
        {"name": "Inbox", "description": "User inbox message APIs."},
        {"name": "Preferences", "description": "User table preference APIs."},
        {"name": "Settings", "description": "System configuration APIs."},
        {"name": "Custom", "description": "Custom module, playbook, and SIEM definition APIs."},
        {"name": "Dashboard", "description": "Dashboard summary APIs."},
        {"name": "Metadata", "description": "Resource metadata APIs."},
        {"name": "Webhooks", "description": "Inbound alert webhook APIs."},
        {"name": "Agent API", "description": "Versioned APIs for agent and CLI integrations."},
        {"name": "System", "description": "System health and utility APIs."},
    ],
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=8),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
}

CORS_ALLOW_ALL_ORIGINS = DEBUG

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

STORAGES = {
    "default": {
        "BACKEND": "apps.attachments.storage.AttachmentS3Storage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}

AWS_S3_ENDPOINT_URL = os.environ.get("RUSTFS_ENDPOINT_URL", "http://localhost:9000")
AWS_ACCESS_KEY_ID = os.environ.get("RUSTFS_ACCESS_KEY")
AWS_SECRET_ACCESS_KEY = os.environ.get("RUSTFS_SECRET_KEY")
AWS_STORAGE_BUCKET_NAME = os.environ.get("RUSTFS_BUCKET", "soc")
AWS_S3_REGION_NAME = os.environ.get("RUSTFS_REGION", "us-east-1")
AWS_S3_ADDRESSING_STYLE = "path"
AWS_S3_SIGNATURE_VERSION = "s3v4"
AWS_S3_CLIENT_CONFIG = Config(
    proxies={},
    s3={"addressing_style": AWS_S3_ADDRESSING_STYLE},
    signature_version=AWS_S3_SIGNATURE_VERSION,
)
AWS_S3_FILE_OVERWRITE = False
AWS_DEFAULT_ACL = None

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOG_LEVEL = os.environ.get("DJANGO_LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get("DJANGO_LOG_FORMAT", "text").lower()
LOG_FORMATTER = "json" if LOG_FORMAT == "json" else "verbose"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": VERBOSE_LOG_FORMAT,
        },
        "json": {
            "()": "apps.common.logging.JsonFormatter",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": LOG_FORMATTER,
        },
    },
    "root": {
        "handlers": ["console"],
        "level": LOG_LEVEL,
    },
    "loggers": {
        "django": {
            "handlers": [],
            "level": os.environ.get("DJANGO_LOG_LEVEL_DJANGO", LOG_LEVEL).upper(),
            "propagate": True,
        },
        "django.request": {
            "handlers": [],
            "level": "WARNING",
            "propagate": True,
        },
        "rest_framework": {
            "handlers": [],
            "level": "WARNING",
            "propagate": True,
        },
    },
}
