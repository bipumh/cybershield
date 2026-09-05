"""Startup bootstrap: schema, roles, tenant, admin + seed compliance data."""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.config import settings
from ..core.constants import Role
from ..db.base import Base
from ..db.models import ComplianceMapping
from ..engines import compliance as compliance_engine
from .rbac_service import seed_default_tenant, seed_roles, get_or_create_user

logger = logging.getLogger("services.bootstrap")


def bootstrap(db: Session) -> None:
    # 1. Ensure schema (idempotent; migrations are the source of truth)
    Base.metadata.create_all(bind=db.bind)

    # 2. Roles
    roles = seed_roles(db)
    logger.info("Seeded %d roles", len(roles))

    # 3. Default tenant + super admin
    tenant = seed_default_tenant(db, settings.default_tenant_name)
    admin = get_or_create_user(
        db, tenant=tenant, email=settings.admin_email,
        password=settings.admin_password, full_name="Platform Administrator",
        role_name=Role.SUPER_ADMIN, is_superuser=True,
    )
    logger.info("Super admin ready: %s", admin.email)

    # 4. Seed curated compliance mappings (defensible, public standards)
    seed_compliance(db)


def seed_compliance(db: Session) -> None:
    count = db.execute(select(ComplianceMapping).limit(1)).scalar_one_or_none()
    if count:
        return
    seeds = [
        ("owasp_top10", "A01:2021", "Broken Access Control", "Attacker can access unauthorized functionality/data.", ["broken_access_control", "cors_misconfiguration", "csrf"]),
        ("owasp_top10", "A02:2021", "Cryptographic Failures", "Weak or missing cryptography exposes sensitive data.", ["tls_configuration", "certificate"]),
        ("owasp_top10", "A03:2021", "Injection", "Untrusted data is interpreted as code/query.", ["injection"]),
        ("owasp_top10", "A05:2021", "Security Misconfiguration", "Insecure default configuration or incomplete hardening.", ["security_misconfiguration", "information_disclosure"]),
        ("owasp_top10", "A06:2021", "Vulnerable and Outdated Components", "Known-vulnerable third-party software in use.", ["outdated_component", "vulnerable_component"]),
        ("owasp_top10", "A07:2021", "Identification and Authentication Failures", "Weak authentication/session management.", ["authentication", "session_security"]),
        ("nist_csf", "ID.RA", "Risk Assessment", "The organization identifies and analyzes risks.", ["vulnerable_component"]),
        ("nist_csf", "PR.AC", "Access Control", "Access to assets is managed.", ["authentication", "broken_access_control"]),
        ("nist_csf", "PR.DS", "Data Security", "Protects confidentiality, integrity, availability.", ["tls_configuration", "security_misconfiguration"]),
        ("nist_csf", "PR.PT", "Protective Technology", "Technical safeguards are deployed.", ["exposed_service", "exposed_management"]),
        ("cis_controls", "v4.4", "Network Segmentation", "Restrict access to network assets.", ["exposed_service"]),
        ("cis_controls", "v5.3", "Secure Network Device Management", "Secure management interfaces.", ["exposed_management"]),
        ("cis_controls", "v6.x", "Access Control Management", "Manage account/access control.", ["authentication"]),
        ("cis_controls", "v7.x", "Continuous Vulnerability Management", "Remediate vulnerabilities continuously.", ["outdated_component", "vulnerable_component"]),
        ("iso_27001", "A.5.10", "Acceptable use of information", "Define rules for asset use.", ["security_misconfiguration"]),
        ("iso_27001", "A.8.8", "Technical vulnerability management", "Manage technical vulnerabilities.", ["outdated_component", "vulnerable_component"]),
        ("iso_27001", "A.8.24", "Use of cryptography", "Deploy appropriate cryptographic controls.", ["tls_configuration", "certificate"]),
    ]
    for standard, control_id, title, desc, cats in seeds:
        db.add(ComplianceMapping(
            standard=standard, control_id=control_id, title=title,
            description=desc, finding_categories="|".join(cats), is_defensible=True,
            source="curated",
        ))
    db.commit()
    logger.info("Seeded %d compliance mappings", len(seeds))
