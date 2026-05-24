"""ORM model registry.

Every model must be imported here so Alembic autogenerate can see it.
"""

from app.db.base import Base
from app.models.alert import Alert
from app.models.api_key import APIKey
from app.models.asset import Asset
from app.models.audit_log import AuditLog
from app.models.billing import Subscription
from app.models.host import Host, HostObservation
from app.models.monitor import Monitor, OwnershipProof
from app.models.organization import Organization, OrganizationMember
from app.models.port import Port
from app.models.risk import RiskScore
from app.models.scan_job import ScanJob
from app.models.screenshot import Screenshot
from app.models.service import Service
from app.models.user import User

__all__ = [
    "Base",
    "Alert",
    "APIKey",
    "Asset",
    "AuditLog",
    "Host",
    "HostObservation",
    "Monitor",
    "Organization",
    "OrganizationMember",
    "OwnershipProof",
    "Port",
    "RiskScore",
    "ScanJob",
    "Screenshot",
    "Service",
    "Subscription",
    "User",
]
