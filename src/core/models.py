"""
Core data models for PatchRank
Defines the unified data structures for vulnerability analysis
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Union
from enum import Enum
import json


# Enums for type safety and consistency
class DependencyType(Enum):
    """Types of dependencies between components"""
    EMBEDDED = "embedded"
    EMBEDDING = "ER"  # Legacy compatibility
    COMMUNICATES = "communicates"
    DEPENDS_ON = "depends_on"
    SHARES_DATA = "shares_data"
    INTER_HOST = "IR"  # Inter-host dependencies
    DATA_RELATED = "DR"  # Data-related dependencies
    SERVICE_RELATED = "SR"  # Service-related dependencies
    NETWORK = "NR"  # Network dependencies
    SECURITY_CONTROL = "SCR"  # Security control dependencies


class CriticalityLevel(Enum):
    """Asset criticality levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    EXTREME = 5


class AnalysisLevel(Enum):
    """Analysis levels supported by the system"""
    ASSET = "asset"
    SYSTEM = "system"


class RiskCalculationStrategy(Enum):
    """Risk calculation strategies"""
    CVSS_ONLY = "cvss_only"
    ENHANCED = "enhanced"
    EPSS_WEIGHTED = "epss_weighted"


@dataclass
class Vulnerability:
    """Represents a vulnerability (CVE) in a component"""
    cve_id: str
    cvss: float = 0.0
    cvss_v3_vector: str = ""
    scope_changed: bool = False
    likelihood: float = 0.0
    impact: float = 0.0
    exploit: bool = False
    epss: float = 0.0
    ransomware: bool = False
    component_id: str = ""
    
    # Additional calculated fields
    exploit_likelihood: float = field(default=0.0, init=False)
    propagation_likelihood: float = field(default=0.0, init=False)
    
    # Resource constraint fields for Task 1.6
    cost: float = field(default=1.0, metadata={"description": "Patch cost in arbitrary units"})
    time_required: float = field(default=1.0, metadata={"description": "Time required to apply patch in hours"})
    
    def __post_init__(self):
        """Validate vulnerability data after initialization"""
        if not self.cve_id:
            raise ValueError("CVE ID is required")
        
        if not (0.0 <= self.cvss <= 10.0):
            raise ValueError("CVSS score must be between 0.0 and 10.0")
        
        if not (0.0 <= self.epss <= 1.0):
            raise ValueError("EPSS score must be between 0.0 and 1.0")
        
        if not (0.0 <= self.likelihood <= 10.0):
            raise ValueError("Likelihood must be between 0.0 and 10.0")
        
        if not (0.0 <= self.impact <= 10.0):
            raise ValueError("Impact must be between 0.0 and 10.0")
        
        # Validate resource constraint fields
        if self.cost < 0.0:
            raise ValueError("Cost must be non-negative")
        
        if self.time_required < 0.0:
            raise ValueError("Time required must be non-negative")
    
    @property
    def scopeChanged(self) -> bool:
        """Backward compatibility property for scopeChanged"""
        return self.scope_changed
    
    @property
    def ransomWare(self) -> bool:
        """Backward compatibility property for ransomWare"""
        return self.ransomware
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary for serialization"""
        return {
            'cve_id': self.cve_id,
            'cvss': self.cvss,
            'cvssV3Vector': self.cvss_v3_vector,
            'scopeChanged': self.scope_changed,
            'likelihood': self.likelihood,
            'impact': self.impact,
            'exploit': self.exploit,
            'epss': self.epss,
            'ransomWare': self.ransomware,
            'component_id': self.component_id,
            'cost': self.cost,
            'time_required': self.time_required
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Vulnerability':
        """Create vulnerability from dictionary"""
        return cls(
            cve_id=data.get('cve_id', ''),
            cvss=data.get('cvss', 0.0),
            cvss_v3_vector=data.get('cvssV3Vector', ''),
            scope_changed=data.get('scopeChanged', False),
            likelihood=data.get('likelihood', 0.0),
            impact=data.get('impact', 0.0),
            exploit=data.get('exploit', False),
            epss=data.get('epss', 0.0),
            ransomware=data.get('ransomWare', False),
            component_id=data.get('component_id', ''),
            cost=data.get('cost', 1.0),
            time_required=data.get('time_required', 1.0)
        )


@dataclass
class Component:
    """Represents a software component with vulnerabilities"""
    id: str
    name: str
    type: str = ""
    vendor: str = ""
    version: str = ""
    embedded_in: Optional[Union[str, int]] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    
    def __post_init__(self):
        """Validate component data after initialization"""
        if not self.id:
            raise ValueError("Component ID is required")
        if not self.name:
            raise ValueError("Component name is required")
    
    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Add a vulnerability to this component"""
        if not isinstance(vulnerability, Vulnerability):
            raise TypeError("Expected Vulnerability object")
        
        # Set the component_id if not already set
        if not vulnerability.component_id:
            vulnerability.component_id = self.id
        
        self.vulnerabilities.append(vulnerability)
    
    def get_vulnerability_count(self) -> int:
        """Get the total number of vulnerabilities in this component"""
        return len(self.vulnerabilities)
    
    def get_critical_vulnerabilities(self, threshold: float = 7.0) -> List[Vulnerability]:
        """Get vulnerabilities with CVSS score above threshold"""
        return [v for v in self.vulnerabilities if v.cvss >= threshold]
    
    def get_highest_cvss(self) -> float:
        """Get the highest CVSS score among all vulnerabilities"""
        if not self.vulnerabilities:
            return 0.0
        return max(v.cvss for v in self.vulnerabilities)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert component to dictionary for serialization"""
        return {
            'id': self.id,
            'name': self.name,
            'type': self.type,
            'vendor': self.vendor,
            'version': self.version,
            'embedded_in': self.embedded_in,
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Component':
        """Create component from dictionary"""
        component = cls(
            id=str(data.get('id', '')),
            name=data.get('name', ''),
            type=data.get('type', ''),
            vendor=data.get('vendor', ''),
            version=data.get('version', ''),
            embedded_in=data.get('embedded_in')
        )
        
        # Add vulnerabilities
        for vuln_data in data.get('vulnerabilities', []):
            vulnerability = Vulnerability.from_dict(vuln_data)
            component.add_vulnerability(vulnerability)
        
        return component


@dataclass
class Asset:
    """Represents a network asset containing multiple components"""
    asset_id: str
    name: str
    asset_type: str = ""
    criticality_level: int = 1
    ip_address: str = "0.0.0.0"
    mac_address: str = "00:00:00:00:00:00"
    components: List[Component] = field(default_factory=list)
    adjacency_matrix: List[List[int]] = field(default_factory=list)
    
    # Additional calculated fields
    total_propagated_risk: float = field(default=0.0, init=False)
    updated_criticality: float = field(default=0.0, init=False)
    final_criticality: float = field(default=0.0, init=False)
    
    def __post_init__(self):
        """Validate asset data after initialization"""
        if not self.asset_id:
            raise ValueError("Asset ID is required")
        if not self.name:
            raise ValueError("Asset name is required")
        if not (1 <= self.criticality_level <= 6):
            raise ValueError("Criticality level must be between 1 and 6")
    
    def add_component(self, component: Component) -> None:
        """Add a component to this asset"""
        if not isinstance(component, Component):
            raise TypeError("Expected Component object")
        self.components.append(component)
    
    def get_vulnerability_count(self) -> int:
        """Get the total number of vulnerabilities across all components"""
        return sum(comp.get_vulnerability_count() for comp in self.components)
    
    def get_all_vulnerabilities(self) -> List[Vulnerability]:
        """Get all vulnerabilities from all components"""
        vulnerabilities = []
        for component in self.components:
            vulnerabilities.extend(component.vulnerabilities)
        return vulnerabilities
    
    def get_component_by_id(self, component_id: str) -> Optional[Component]:
        """Get a component by its ID"""
        for component in self.components:
            if component.id == component_id:
                return component
        return None
    
    def set_adjacency_matrix(self, matrix: List[List[int]]) -> None:
        """Set the adjacency matrix for component dependencies"""
        if len(matrix) != len(self.components):
            raise ValueError("Adjacency matrix size must match component count")
        
        for row in matrix:
            if len(row) != len(self.components):
                raise ValueError("Adjacency matrix must be square")
        
        self.adjacency_matrix = matrix
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert asset to dictionary for serialization"""
        return {
            'asset_id': self.asset_id,
            'name': self.name,
            'type': self.asset_type,
            'criticality_level': self.criticality_level,
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'components': [comp.to_dict() for comp in self.components],
            'adjacency_matrix': self.adjacency_matrix
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Asset':
        """Create asset from dictionary"""
        asset = cls(
            asset_id=str(data.get('asset_id', '')),
            name=data.get('name', ''),
            asset_type=data.get('type', ''),
            criticality_level=data.get('criticality_level', 1),
            ip_address=data.get('ip_address', '0.0.0.0'),
            mac_address=data.get('mac_address', '00:00:00:00:00:00')
        )
        
        # Add components
        for comp_data in data.get('components', []):
            component = Component.from_dict(comp_data)
            asset.add_component(component)
        
        # Set adjacency matrix if present
        adjacency_matrix = data.get('adjacency_matrix', [])
        if adjacency_matrix:
            asset.set_adjacency_matrix(adjacency_matrix)
        
        return asset


@dataclass
class System:
    """Represents a system containing multiple assets and their connections"""
    assets: List[Asset] = field(default_factory=list)
    connections: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_asset(self, asset: Asset) -> None:
        """Add an asset to this system"""
        if not isinstance(asset, Asset):
            raise TypeError("Expected Asset object")
        self.assets.append(asset)
    
    def add_connection(self, connection: Dict[str, Any]) -> None:
        """Add a network connection between assets"""
        # Support both IP-based and asset ID-based connection formats
        ip_based = all(field in connection for field in ['src_ip', 'dst_ip'])
        asset_id_based = all(field in connection for field in ['source_asset_id', 'destination_asset_id'])
        
        if not (ip_based or asset_id_based):
            raise ValueError(f"Connection must contain either ['src_ip', 'dst_ip'] or ['source_asset_id', 'destination_asset_id']")
        
        self.connections.append(connection)
    
    def get_vulnerability_count(self) -> int:
        """Get the total number of vulnerabilities across all assets"""
        return sum(asset.get_vulnerability_count() for asset in self.assets)
    
    def get_all_vulnerabilities(self) -> List[Vulnerability]:
        """Get all vulnerabilities from all assets"""
        vulnerabilities = []
        for asset in self.assets:
            vulnerabilities.extend(asset.get_all_vulnerabilities())
        return vulnerabilities
    
    def get_asset_by_id(self, asset_id: str) -> Optional[Asset]:
        """Get an asset by its ID"""
        for asset in self.assets:
            if asset.asset_id == asset_id:
                return asset
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert system to dictionary for serialization"""
        return {
            'Assets': [asset.to_dict() for asset in self.assets],
            'Connections': self.connections
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'System':
        """Create system from dictionary"""
        system = cls()
        
        # Add assets
        for asset_data in data.get('Assets', []):
            asset = Asset.from_dict(asset_data)
            system.add_asset(asset)
        
        # Add connections
        for connection in data.get('Connections', []):
            system.add_connection(connection)
        
        return system


# Export all classes and enums
__all__ = [
    'Vulnerability', 'Component', 'Asset', 'System',
    'DependencyType', 'CriticalityLevel', 'AnalysisLevel', 'RiskCalculationStrategy'
] 