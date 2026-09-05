"""Domain constants shared across the platform.

These centralize enums and controlled vocabularies so the risk engine,
scanners, API validation and UI remain consistent.
"""
from __future__ import annotations


class Severity:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    ORDER = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}
    ALL = [CRITICAL, HIGH, MEDIUM, LOW, INFO]


class RiskBand:
    """Normalized 0-100 risk classification."""
    CRITICAL = "critical"  # 90-100
    HIGH = "high"          # 70-89
    MEDIUM = "medium"      # 40-69
    LOW = "low"            # 1-39

    BOUNDARIES = [
        (1, 39, LOW),
        (40, 69, MEDIUM),
        (70, 89, HIGH),
        (90, 100, CRITICAL),
    ]

    @classmethod
    def band_for(cls, score: int) -> str:
        for lo, hi, band in cls.BOUNDARIES:
            if lo <= score <= hi:
                return band
        return cls.LOW


class AssetType:
    SERVER = "server"
    WORKSTATION = "workstation"
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    WIRELESS_CONTROLLER = "wireless_controller"
    ACCESS_POINT = "access_point"
    NETWORK_APPLIANCE = "network_appliance"
    DATABASE_SERVER = "database_server"
    APPLICATION_SERVER = "application_server"
    VIRTUAL_MACHINE = "virtual_machine"
    CONTAINER_HOST = "container_host"
    STORAGE_DEVICE = "storage_device"
    IOT_DEVICE = "iot_device"
    DOMAIN = "domain"
    WEB_APPLICATION = "web_application"
    API_ENDPOINT = "api_endpoint"
    OTHER = "other"

    ALL = [SERVER, WORKSTATION, ROUTER, SWITCH, FIREWALL, WIRELESS_CONTROLLER,
           ACCESS_POINT, NETWORK_APPLIANCE, DATABASE_SERVER, APPLICATION_SERVER,
           VIRTUAL_MACHINE, CONTAINER_HOST, STORAGE_DEVICE, IOT_DEVICE,
           DOMAIN, WEB_APPLICATION, API_ENDPOINT, OTHER]


class AssetCriticality:
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    ALL = [CRITICAL, HIGH, MEDIUM, LOW]


class Environment:
    PRODUCTION = "production"
    NON_PRODUCTION = "non_production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    ALL = [PRODUCTION, NON_PRODUCTION, STAGING, DEVELOPMENT, TEST]


class FindingStatus:
    OPEN = "open"
    INVESTIGATING = "investigating"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATION_PLANNED = "remediation_planned"
    REMEDIATION_IN_PROGRESS = "remediation_in_progress"
    RESOLVED = "resolved"
    VERIFIED = "verified"
    CLOSED = "closed"

    ACTIVE = {OPEN, INVESTIGATING, ACCEPTED_RISK, REMEDIATION_PLANNED,
              REMEDIATION_IN_PROGRESS}
    CLOSED_STATES = {RESOLVED, VERIFIED, CLOSED, FALSE_POSITIVE}
    ALL = [OPEN, INVESTIGATING, FALSE_POSITIVE, ACCEPTED_RISK,
           REMEDIATION_PLANNED, REMEDIATION_IN_PROGRESS,
           RESOLVED, VERIFIED, CLOSED]


class ChangeType:
    NEW = "new"
    FIXED = "fixed"
    PERSISTENT = "persistent"
    REOPENED = "reopened"
    CHANGED = "changed"
    ALL = [NEW, FIXED, PERSISTENT, REOPENED, CHANGED]


class RemediationLevel:
    """Level 1 safe-auto / Level 2 approval / Level 3 manual."""
    LEVEL1_SAFE_AUTO = "level1_safe_auto"
    LEVEL2_APPROVAL_REQUIRED = "level2_approval_required"
    LEVEL3_MANUAL = "level3_manual"
    ALL = [LEVEL1_SAFE_AUTO, LEVEL2_APPROVAL_REQUIRED, LEVEL3_MANUAL]


class RemediationStatus:
    PROPOSED = "proposed"
    RISK_REVIEW = "risk_review"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    EXECUTED = "executed"
    VERIFICATION_PENDING = "verification_pending"
    VERIFIED = "verified"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    CLOSED = "closed"
    ALL = [
        PROPOSED, RISK_REVIEW, PENDING_APPROVAL, APPROVED, REJECTED,
        EXECUTING, EXECUTED, VERIFICATION_PENDING, VERIFIED, ROLLED_BACK,
        FAILED, CLOSED,
    ]


class ScanProfile:
    PASSIVE = "passive"
    SAFE = "safe"
    STANDARD = "standard"
    ENTERPRISE = "enterprise"
    ALL = [PASSIVE, SAFE, STANDARD, ENTERPRISE]

    # Profile -> effective-safe concurrency / request cap multipliers
    CONCURRENCY = {PASSIVE: 1, SAFE: 2, STANDARD: 4, ENTERPRISE: 2}
    RATE_CAP = {PASSIVE: 20, SAFE: 40, STANDARD: 80, ENTERPRISE: 30}


class ScanTargetKind:
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    CIDR = "cidr"
    HOSTNAME = "hostname"
    RANGE = "range"
    ASSET = "asset"
    ALL = [DOMAIN, URL, IP, CIDR, HOSTNAME, RANGE, ASSET]


class ScanStatus:
    PENDING = "pending"
    VALIDATING = "validating"
    DISCOVERING = "discovering"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    CANCELLED = "cancelled"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ALL = [PENDING, VALIDATING, DISCOVERING, AWAITING_APPROVAL, RUNNING,
           COMPLETED, COMPLETED_WITH_ERRORS, CANCELLED, FAILED, TIMEOUT]


class ScanMode:
    WEB = "web"
    NETWORK = "network"


class ScanSchedule:
    ONETIME = "onetime"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"
    ALL = [ONETIME, DAILY, WEEKLY, MONTHLY, CUSTOM]


class ReportFormat:
    PDF = "pdf"
    HTML = "html"
    CSV = "csv"
    JSON = "json"
    XLSX = "xlsx"
    ALL = [PDF, HTML, CSV, JSON, XLSX]


class ReportType:
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    COMPLIANCE = "compliance"
    ALL = [EXECUTIVE, TECHNICAL, COMPLIANCE]


class ExceptionKind:
    """Reasons for marking a finding as false positive / accepted risk."""
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    COMPENSATING_CONTROL = "compensating_control"
    ALL = [FALSE_POSITIVE, ACCEPTED_RISK, COMPENSATING_CONTROL]


# ─── Roles ──────────────────────────────────────────────────────────────
class Role:
    SUPER_ADMIN = "super_admin"
    CISO = "ciso"
    SECURITY_ANALYST = "security_analyst"
    SOC_ANALYST = "soc_analyst"
    NETWORK_ADMIN = "network_admin"
    SYSTEM_ADMIN = "system_admin"
    APP_SECURITY_ANALYST = "app_security_analyst"
    REMEDIATION_ENGINEER = "remediation_engineer"
    AUDITOR = "auditor"
    MANAGEMENT = "management"

    ALL = [SUPER_ADMIN, CISO, SECURITY_ANALYST, SOC_ANALYST, NETWORK_ADMIN,
           SYSTEM_ADMIN, APP_SECURITY_ANALYST, REMEDIATION_ENGINEER,
           AUDITOR, MANAGEMENT]

    # Role -> list of permission identifiers
    PERMISSIONS = {
        SUPER_ADMIN: ["*"],
        CISO: [
            "assets:read", "scans:read", "scans:create", "scans:approve",
            "vulns:read", "vulns:manage", "remediation:read",
            "remediation:approve", "reports:create", "reports:read",
            "compliance:read", "dashboard:read", "risk:read", "ai:read",
            "audit:read", "admin:read", "exceptions:approve",
        ],
        SECURITY_ANALYST: [
            "assets:read", "scans:create", "scans:read", "vulns:read",
            "vulns:manage", "findings:manage", "remediation:read",
            "remediation:modify", "reports:create", "compliance:read",
            "dashboard:read", "risk:read", "ai:read", "exceptions:create",
        ],
        SOC_ANALYST: [
            "assets:read", "scans:read", "vulns:read", "dashboard:read",
            "ai:read", "audit:read", "remediation:read",
        ],
        NETWORK_ADMIN: [
            "assets:read", "assets:modify", "scans:create", "scans:read",
            "vulns:read", "remediation:read", "remediation:execute",
            "dashboard:read", "network:read",
        ],
        SYSTEM_ADMIN: [
            "assets:read", "assets:modify", "scans:create", "scans:read",
            "vulns:read", "remediation:read", "remediation:execute",
            "dashboard:read",
        ],
        APP_SECURITY_ANALYST: [
            "assets:read", "scans:create", "scans:read", "vulns:read",
            "vulns:manage", "reports:create", "compliance:read",
            "dashboard:read", "ai:read",
        ],
        REMEDIATION_ENGINEER: [
            "assets:read", "vulns:read", "remediation:read",
            "remediation:execute", "remediation:verify",
        ],
        AUDITOR: [
            "assets:read", "scans:read", "vulns:read", "reports:read",
            "compliance:read", "audit:read", "dashboard:read",
        ],
        MANAGEMENT: [
            "dashboard:read", "reports:read", "risk:read", "compliance:read",
        ],
    }


# ─── Compliance standards (mappable, never invented) ───────────────────
class Standard:
    OWASP_TOP10 = "owasp_top10"
    OWASP_ASVS = "owasp_asvs"
    OWASP_WSTG = "owasp_wstg"
    OWASP_API = "owasp_api_top10"
    CWE = "cwe"
    CVSS = "cvss"
    NIST_CSF = "nist_csf"
    NIST_800_53 = "nist_800_53"
    CIS_CONTROLS = "cis_controls"
    CISA_KEV = "cisa_kev"
    ISO_27001 = "iso_27001"
    PCI_DSS = "pci_dss"
    ALL = [OWASP_TOP10, OWASP_ASVS, OWASP_WSTG, OWASP_API, CWE, CVSS,
           NIST_CSF, NIST_800_53, CIS_CONTROLS, CISA_KEV, ISO_27001, PCI_DSS]
