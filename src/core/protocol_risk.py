"""
Protocol and Service Risk Database
Manages protocol and port risk assessments for network risk calculation
"""

from typing import Dict, Optional, Any
import json
import logging

logger = logging.getLogger(__name__)


class ProtocolRiskDatabase:
    """Manages protocol and port risk assessments"""
    
    def __init__(self, config_path: Optional[str] = None):
        # Default protocol risks
        self.protocol_risks = {
            # Critical risk
            "TELNET": 0.95,
            "SMB": 0.90,
            "RDP": 0.85,
            "VNC": 0.90,
            "FTP": 0.85,
            
            # High risk
            "HTTP": 0.80,
            "LDAP": 0.70,
            "SNMP": 0.75,
            "SMTP": 0.70,
            "POP3": 0.75,
            "IMAP": 0.70,
            
            # Medium risk
            "HTTPS": 0.60,
            "SQL": 0.65,
            "DNS": 0.55,
            "NTP": 0.50,
            "DHCP": 0.45,
            
            # Low risk
            "SSH": 0.40,
            "IPSEC": 0.30,
            "ICMP": 0.25,
            "TLS": 0.35,
            "SSL": 0.35,
            
            # Default
            "TCP": 0.60,
            "UDP": 0.55
        }
        
        # Port-specific multipliers
        self.port_multipliers = {
            23: 1.5,     # Telnet
            445: 1.4,    # SMB
            139: 1.4,    # NetBIOS
            3389: 1.3,   # RDP
            135: 1.3,    # RPC
            21: 1.2,     # FTP
            1433: 1.2,   # MSSQL
            3306: 1.2,   # MySQL
            389: 1.2,    # LDAP
            636: 1.1,    # LDAPS
            80: 1.1,     # HTTP
            8080: 1.1,   # HTTP alternate
            443: 0.8,    # HTTPS
            22: 0.6,     # SSH
            25: 1.0,     # SMTP
            110: 1.0,    # POP3
            143: 1.0,    # IMAP
            53: 0.8,     # DNS
            161: 1.1,    # SNMP
            5900: 1.3,   # VNC
        }
        
        # Service-specific adjustments
        self.service_factors = {
            "encrypted": 0.7,
            "authenticated": 0.6,
            "vpn": 0.5,
            "management": 0.4,
            "database": 0.8,
            "web": 0.7,
            "email": 0.6,
            "file_transfer": 0.8,
            "remote_access": 0.9,
            "directory": 0.7,
        }
        
        # Protocol-specific exposure factors
        self.exposure_factors = {
            "TELNET": 1.0,   # No encryption
            "HTTP": 0.9,     # Plain text
            "FTP": 0.9,      # Plain text
            "SMTP": 0.8,     # Plain text
            "SNMP": 0.8,     # Often unencrypted
            "HTTPS": 0.6,    # Encrypted
            "SSH": 0.4,      # Encrypted
            "LDAPS": 0.5,    # Encrypted LDAP
            "IPSEC": 0.3,    # Strong encryption
        }
        
        if config_path:
            self.load_from_file(config_path)
    
    def load_from_file(self, config_path: str):
        """Load protocol risk configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Update protocol risks
            if 'protocol_risks' in config:
                self.protocol_risks.update(config['protocol_risks'])
                logger.debug(f"Loaded {len(config['protocol_risks'])} protocol risk entries")
            
            # Update port multipliers
            if 'port_multipliers' in config:
                self.port_multipliers.update(config['port_multipliers'])
                logger.debug(f"Loaded {len(config['port_multipliers'])} port multiplier entries")
            
            # Update service factors
            if 'service_factors' in config:
                self.service_factors.update(config['service_factors'])
                logger.debug(f"Loaded {len(config['service_factors'])} service factor entries")
            
            # Update exposure factors
            if 'exposure_factors' in config:
                self.exposure_factors.update(config['exposure_factors'])
                logger.debug(f"Loaded {len(config['exposure_factors'])} exposure factor entries")
                
        except FileNotFoundError:
            logger.warning(f"Protocol risk configuration file not found: {config_path}, using defaults")
        except Exception as e:
            logger.error(f"Error loading protocol risk configuration: {e}")
    
    def get_protocol_risk(self, protocol: str, port: int = 0, 
                         service_type: Optional[str] = None) -> float:
        """Get comprehensive risk score for a protocol/port combination"""
        # Base protocol risk
        base_risk = self.protocol_risks.get(protocol.upper(), 0.5)
        
        # Port multiplier
        port_mult = self.port_multipliers.get(port, 1.0)
        
        # Service type adjustment
        service_mult = 1.0
        if service_type:
            service_mult = self.service_factors.get(service_type, 1.0)
        
        # Calculate final risk
        risk = base_risk * port_mult * service_mult
        
        # Ensure risk is within bounds
        risk = max(0.01, min(1.0, risk))
        
        logger.debug(f"Protocol risk: {protocol}:{port} ({service_type}) = {risk:.3f} (base={base_risk:.3f}, port={port_mult:.3f}, service={service_mult:.3f})")
        
        return risk
    
    def get_exposure_factor(self, protocol: str) -> float:
        """Get exposure factor for a protocol based on encryption/security"""
        factor = self.exposure_factors.get(protocol.upper(), 0.6)  # Default medium exposure
        logger.debug(f"Exposure factor for {protocol}: {factor:.3f}")
        return factor
    
    def get_comprehensive_risk(self, protocol: str, port: int = 0, 
                              service_type: Optional[str] = None,
                              include_exposure: bool = True) -> float:
        """Get comprehensive risk including exposure factors"""
        # Get base protocol risk
        risk = self.get_protocol_risk(protocol, port, service_type)
        
        # Include exposure factor if requested
        if include_exposure:
            exposure = self.get_exposure_factor(protocol)
            risk = (risk + exposure) / 2  # Average of risk and exposure
        
        return max(0.01, min(1.0, risk))
    
    def get_protocol_info(self, protocol: str) -> Dict[str, Any]:
        """Get comprehensive information about a protocol"""
        return {
            'protocol': protocol.upper(),
            'base_risk': self.protocol_risks.get(protocol.upper(), 0.5),
            'exposure_factor': self.get_exposure_factor(protocol),
            'common_ports': [port for port, mult in self.port_multipliers.items() 
                           if mult > 1.0 and protocol.upper() in ['HTTP', 'HTTPS', 'SSH', 'FTP', 'SMTP']],
            'risk_level': self._get_risk_level(self.protocol_risks.get(protocol.upper(), 0.5))
        }
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Convert risk score to risk level description"""
        if risk_score >= 0.8:
            return "CRITICAL"
        elif risk_score >= 0.6:
            return "HIGH"
        elif risk_score >= 0.4:
            return "MEDIUM"
        else:
            return "LOW"
