"""Product constants and Kemenkes-aligned visual tokens."""
from datetime import time

PRODUCT_NAME = "T-ERABYTE CSIRT SOC PRO"
PRODUCT_SUBTITLE = "Continuous Behavioral Security Assurance & Real-Time Security Intelligence Platform"
ORGANIZATION = "Kementerian Kesehatan Republik Indonesia"
TEAM_NAME = "Tim CSIRT Kementerian Kesehatan Republik Indonesia"
RELEASE_DATE = "10 October 2026"
VERSION = "9.0.0"
DEFAULT_TIMEZONE = "Asia/Jakarta"
DEFAULT_OFFICE_START = time(8, 0)
DEFAULT_OFFICE_END = time(17, 0)

KEMENKES_COLORS = {
    "turquoise": "#00A7A0",
    "turquoise_medium": "#5CC6C0",
    "lime": "#C8D72A",
    "grey": "#6B7280",
    "ink": "#18323A",
    "surface": "#F7FBFA",
    "white": "#FFFFFF",
}

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
RISK_LABELS = [(0, "INFO"), (1, "LOW"), (30, "MEDIUM"), (60, "HIGH"), (80, "CRITICAL")]
