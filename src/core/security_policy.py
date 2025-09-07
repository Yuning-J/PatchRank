"""
Security Policy Configuration Module
Provides configurable security zones and policies for network risk calculation
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class SecurityZone:
    """Represents a security zone in the network"""
    name: str
    trust_level: int  # 1-10, higher = more trusted
    asset_criteria: Dict[str, Any]  # Criteria for asset membership


@dataclass
class SecurityPolicy:
    """Represents security policies between zones or specific connections"""
    source: str  # Zone name or specific IP
    destination: str  # Zone name or specific IP
    action: str  # 'allow', 'deny', 'restrict'
    probability_factor: float  # 0.0-1.0, affects edge success probability
    conditions: Dict[str, Any]  # Additional conditions


class SecurityConfiguration:
    """Manages security configuration for network risk calculation"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.zones: Dict[str, SecurityZone] = {}
        self.policies: List[SecurityPolicy] = []
        self.connection_rules: Dict[Tuple[str, str], float] = {}
        
        if config_path:
            self.load_from_file(config_path)
    
    def load_from_file(self, config_path: str):
        """Load security configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Load zones
            for zone_data in config.get('security_zones', []):
                zone = SecurityZone(**zone_data)
                self.zones[zone.name] = zone
                logger.debug(f"Loaded security zone: {zone.name} (trust_level={zone.trust_level})")
            
            # Load policies
            for policy_data in config.get('security_policies', []):
                policy = SecurityPolicy(**policy_data)
                self.policies.append(policy)
                logger.debug(f"Loaded security policy: {policy.source} -> {policy.destination} ({policy.action})")
            
            # Load specific connection rules
            for rule in config.get('connection_rules', []):
                key = (rule['source'], rule['destination'])
                self.connection_rules[key] = rule['factor']
                logger.debug(f"Loaded connection rule: {rule['source']} -> {rule['destination']} (factor={rule['factor']})")
                
        except FileNotFoundError:
            logger.warning(f"Security configuration file not found: {config_path}, using defaults")
        except Exception as e:
            logger.error(f"Error loading security configuration: {e}")
    
    def get_zone_for_asset(self, asset) -> Optional[str]:
        """Determine which security zone an asset belongs to"""
        for zone_name, zone in self.zones.items():
            # Check criticality-based assignment
            if 'criticality_range' in zone.asset_criteria:
                min_crit, max_crit = zone.asset_criteria['criticality_range']
                if min_crit <= asset.criticality_level <= max_crit:
                    logger.debug(f"Asset {asset.name} assigned to zone {zone_name} (criticality={asset.criticality_level})")
                    return zone_name
            
            # Check name-based assignment
            if 'name_pattern' in zone.asset_criteria:
                pattern = zone.asset_criteria['name_pattern'].lower()
                if pattern in asset.name.lower():
                    logger.debug(f"Asset {asset.name} assigned to zone {zone_name} (name_pattern={pattern})")
                    return zone_name
            
            # Check IP range assignment
            if 'ip_range' in zone.asset_criteria and hasattr(asset, 'ip_address'):
                # Simple subnet check (can be enhanced)
                ip_prefix = zone.asset_criteria['ip_range']
                if asset.ip_address.startswith(ip_prefix):
                    logger.debug(f"Asset {asset.name} assigned to zone {zone_name} (ip_range={ip_prefix})")
                    return zone_name
        
        logger.debug(f"Asset {asset.name} assigned to default zone")
        return 'default'
    
    def get_connection_factor(self, src_asset, dst_asset) -> float:
        """Get security policy factor for a connection"""
        # Check specific IP rules first
        if hasattr(src_asset, 'ip_address') and hasattr(dst_asset, 'ip_address'):
            key = (src_asset.ip_address, dst_asset.ip_address)
            logger.debug(f"Checking connection rule for {key}")
            if key in self.connection_rules:
                factor = self.connection_rules[key]
                logger.info(f"Found specific connection rule: {src_asset.ip_address} -> {dst_asset.ip_address} = {factor}")
                return factor
            else:
                logger.debug(f"No specific rule found for {key}, checking zones...")
        
        # Check zone-based policies
        src_zone = self.get_zone_for_asset(src_asset)
        dst_zone = self.get_zone_for_asset(dst_asset)
        
        for policy in self.policies:
            if policy.source == src_zone and policy.destination == dst_zone:
                if policy.action == 'deny':
                    logger.debug(f"Connection denied by policy: {src_zone} -> {dst_zone}")
                    return 0.0
                elif policy.action == 'restrict':
                    logger.debug(f"Connection restricted by policy: {src_zone} -> {dst_zone} (factor={policy.probability_factor})")
                    return policy.probability_factor
                else:  # allow
                    logger.debug(f"Connection allowed by policy: {src_zone} -> {dst_zone}")
                    return 1.0
        
        # Default zone transition factors based on trust levels
        if src_zone in self.zones and dst_zone in self.zones:
            src_trust = self.zones[src_zone].trust_level
            dst_trust = self.zones[dst_zone].trust_level
            
            # Calculate factor based on trust difference
            trust_diff = abs(dst_trust - src_trust)
            if dst_trust < src_trust:  # Moving to less trusted zone
                factor = max(0.2, 1.0 - trust_diff * 0.15)
            else:  # Moving to more trusted zone
                factor = max(0.1, 1.0 - trust_diff * 0.2)
            
            logger.debug(f"Zone transition factor: {src_zone}({src_trust}) -> {dst_zone}({dst_trust}) = {factor}")
            return factor
        
        logger.debug(f"Default connection factor: {src_asset.ip_address} -> {dst_asset.ip_address} = 0.5")
        return 0.5  # Default factor
