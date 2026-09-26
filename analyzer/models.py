"""
Core data models for APK Stack Analyzer.
These are the canonical data structures used throughout the analyzer,
backend API, and CLI.
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional
import json


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EvidenceStrength(str, Enum):
    STRONG = "strong"
    MEDIUM = "medium"
    WEAK = "weak"


class EvidenceType(str, Enum):
    NATIVE_LIBRARY = "native_library"
    DEX_CLASS = "dex_class"
    DEX_PACKAGE = "dex_package"
    ASSET_FILE = "asset_file"
    MANIFEST_ATTRIBUTE = "manifest_attribute"
    MANIFEST_COMPONENT = "manifest_component"
    RESOURCE_FILE = "resource_file"
    META_INF = "meta_inf"
    FILE_STRUCTURE = "file_structure"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class PermissionGroup(str, Enum):
    NORMAL = "normal"
    DANGEROUS = "dangerous"
    SPECIAL = "special"
    CUSTOM = "custom"


class SecuritySeverity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AnalysisStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    type: EvidenceType
    artifact: str
    strength: EvidenceStrength
    description: str = ""
    location: str = ""          # file path inside APK

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "artifact": self.artifact,
            "strength": self.strength.value,
            "description": self.description,
            "location": self.location,
        }


@dataclass
class NegativeEvidence:
    """An artifact that was expected but NOT found — reduces confidence in a framework."""
    artifact: str
    description: str = ""

    def to_dict(self) -> dict:
        return {"artifact": self.artifact, "description": self.description}


# ---------------------------------------------------------------------------
# Framework Detection
# ---------------------------------------------------------------------------

@dataclass
class FrameworkDetection:
    name: str
    confidence: Confidence
    evidence: list[Evidence] = field(default_factory=list)
    negative_evidence: list[NegativeEvidence] = field(default_factory=list)
    sub_technologies: dict[str, str] = field(default_factory=dict)
    # e.g. {"runtime": "Hermes", "ui_toolkit": "Jetpack Compose"}

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "confidence": self.confidence.value,
            "evidence": [e.to_dict() for e in self.evidence],
            "negative_evidence": [n.to_dict() for n in self.negative_evidence],
            "sub_technologies": self.sub_technologies,
        }


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

@dataclass
class AndroidComponent:
    name: str
    component_type: str      # activity | service | receiver | provider
    exported: Optional[bool] = None
    intent_filters: list[str] = field(default_factory=list)
    attributes: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "component_type": self.component_type,
            "exported": self.exported,
            "intent_filters": self.intent_filters,
            "attributes": self.attributes,
        }


@dataclass
class Permission:
    name: str
    group: PermissionGroup
    description: str = ""
    is_sensitive: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "group": self.group.value,
            "description": self.description,
            "is_sensitive": self.is_sensitive,
        }


@dataclass
class ManifestAnalysis:
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    compile_sdk: Optional[int] = None
    debuggable: bool = False
    allow_backup: bool = True
    network_security_config: bool = False
    uses_cleartext_traffic: Optional[bool] = None
    application_label: str = ""
    application_icon: str = ""
    activities: list[AndroidComponent] = field(default_factory=list)
    services: list[AndroidComponent] = field(default_factory=list)
    receivers: list[AndroidComponent] = field(default_factory=list)
    providers: list[AndroidComponent] = field(default_factory=list)
    permissions: list[Permission] = field(default_factory=list)
    uses_permissions: list[str] = field(default_factory=list)
    raw_attributes: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "version_name": self.version_name,
            "version_code": self.version_code,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "compile_sdk": self.compile_sdk,
            "debuggable": self.debuggable,
            "allow_backup": self.allow_backup,
            "network_security_config": self.network_security_config,
            "uses_cleartext_traffic": self.uses_cleartext_traffic,
            "application_label": self.application_label,
            "application_icon": self.application_icon,
            "activities": [c.to_dict() for c in self.activities],
            "services": [c.to_dict() for c in self.services],
            "receivers": [c.to_dict() for c in self.receivers],
            "providers": [c.to_dict() for c in self.providers],
            "permissions": [p.to_dict() for p in self.permissions],
            "uses_permissions": self.uses_permissions,
        }


# ---------------------------------------------------------------------------
# Native Libraries
# ---------------------------------------------------------------------------

@dataclass
class NativeLibrary:
    name: str
    abi: str            # arm64-v8a | armeabi-v7a | x86 | x86_64
    size_bytes: int = 0
    detected_purpose: str = ""
    framework_hint: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "abi": self.abi,
            "size_bytes": self.size_bytes,
            "detected_purpose": self.detected_purpose,
            "framework_hint": self.framework_hint,
        }


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

@dataclass
class Dependency:
    name: str
    version: str = ""           # may be empty if not determinable
    evidence_type: str = ""     # DEX package, asset file, etc.
    confidence: Confidence = Confidence.MEDIUM
    package_prefix: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "evidence_type": self.evidence_type,
            "confidence": self.confidence.value,
            "package_prefix": self.package_prefix,
        }


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

@dataclass
class AssetEntry:
    path: str
    size_bytes: int = 0
    category: str = ""          # js_bundle | font | config | certificate | model | localization | web_asset | other
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "category": self.category,
            "description": self.description,
        }


# ---------------------------------------------------------------------------
# URL Detection
# ---------------------------------------------------------------------------

@dataclass
class DetectedURL:
    url: str
    category: str = "unknown"   # api | authentication | analytics | cdn | web | unknown
    source_file: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "category": self.category,
            "source_file": self.source_file,
        }


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

@dataclass
class SecurityFinding:
    title: str
    severity: SecuritySeverity
    description: str
    recommendation: str = ""
    requires_manual_verification: bool = True
    source: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "recommendation": self.recommendation,
            "requires_manual_verification": self.requires_manual_verification,
            "source": self.source,
        }


# ---------------------------------------------------------------------------
# File Tree
# ---------------------------------------------------------------------------

@dataclass
class FileTreeNode:
    name: str
    path: str
    is_dir: bool
    size_bytes: int = 0
    children: list["FileTreeNode"] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "is_dir": self.is_dir,
            "size_bytes": self.size_bytes,
            "children": [c.to_dict() for c in self.children],
        }


# ---------------------------------------------------------------------------
# DEX Analysis
# ---------------------------------------------------------------------------

@dataclass
class DexAnalysis:
    dex_files: list[str] = field(default_factory=list)
    total_classes: int = 0
    total_methods: int = 0
    packages: list[str] = field(default_factory=list)
    # top-level packages only to keep payload manageable
    framework_packages: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "dex_files": self.dex_files,
            "total_classes": self.total_classes,
            "total_methods": self.total_methods,
            "packages": self.packages,
            "framework_packages": self.framework_packages,
        }


# ---------------------------------------------------------------------------
# APK Metadata
# ---------------------------------------------------------------------------

@dataclass
class APKMetadata:
    filename: str = ""
    file_size_bytes: int = 0
    sha256: str = ""
    analysis_id: str = ""
    apk_path: str = ""
    # Tools
    jadx_available: bool = False
    apktool_available: bool = False

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "file_size_bytes": self.file_size_bytes,
            "sha256": self.sha256,
            "analysis_id": self.analysis_id,
            "jadx_available": self.jadx_available,
            "apktool_available": self.apktool_available,
        }


# ---------------------------------------------------------------------------
# Full Analysis Result
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "1.0"

@dataclass
class AnalysisResult:
    schema_version: str = SCHEMA_VERSION
    metadata: APKMetadata = field(default_factory=APKMetadata)
    manifest: ManifestAnalysis = field(default_factory=ManifestAnalysis)
    frameworks: list[FrameworkDetection] = field(default_factory=list)
    primary_framework: Optional[FrameworkDetection] = None
    is_hybrid: bool = False
    architectures: list[str] = field(default_factory=list)
    native_libraries: list[NativeLibrary] = field(default_factory=list)
    dex_analysis: DexAnalysis = field(default_factory=DexAnalysis)
    dependencies: list[Dependency] = field(default_factory=list)
    assets: list[AssetEntry] = field(default_factory=list)
    urls: list[DetectedURL] = field(default_factory=list)
    security_findings: list[SecurityFinding] = field(default_factory=list)
    file_tree: Optional[FileTreeNode] = None
    all_evidence: list[Evidence] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "metadata": self.metadata.to_dict(),
            "manifest": self.manifest.to_dict(),
            "frameworks": [f.to_dict() for f in self.frameworks],
            "primary_framework": self.primary_framework.to_dict() if self.primary_framework else None,
            "is_hybrid": self.is_hybrid,
            "architectures": self.architectures,
            "native_libraries": [l.to_dict() for l in self.native_libraries],
            "dex_analysis": self.dex_analysis.to_dict(),
            "dependencies": [d.to_dict() for d in self.dependencies],
            "assets": [a.to_dict() for a in self.assets],
            "urls": [u.to_dict() for u in self.urls],
            "security_findings": [s.to_dict() for s in self.security_findings],
            "file_tree": self.file_tree.to_dict() if self.file_tree else None,
            "all_evidence": [e.to_dict() for e in self.all_evidence],
            "errors": self.errors,
            "warnings": self.warnings,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
