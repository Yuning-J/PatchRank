"""
Unified data loading module for PatchRank
Handles loading of asset-level and system-level data with proper validation
"""

import json
import os
from typing import Union, Dict, Any, Optional
from pathlib import Path

from .models import Asset, System, Vulnerability, Component


class DataLoader:
    """Unified data loader for both asset and system level data"""
    
    def __init__(self, data_path: str):
        """
        Initialize the data loader
        
        Args:
            data_path: Path to the data directory
        """
        if not data_path:
            raise ValueError("data_path cannot be None or empty")
        self.data_path = Path(data_path)
        if not self.data_path.exists():
            raise ValueError(f"Data path does not exist: {data_path}")
    
    def load_data(self, filename: str) -> Union[Asset, System]:
        """
        Load data from a JSON file, automatically detecting if it's asset or system level
        
        Args:
            filename: Name of the JSON file to load
            
        Returns:
            Asset or System object depending on the data structure
        """
        file_path = self.data_path / filename
        if not file_path.exists():
            raise FileNotFoundError(f"Data file not found: {file_path}")
        
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        # Determine if this is system-level or asset-level data
        if self._is_system_data(data):
            return self._load_system_data(data)
        else:
            return self._load_asset_data(data)
    
    def _is_system_data(self, data: Dict[str, Any]) -> bool:
        """
        Determine if the data represents a system (multiple assets) or single asset
        
        Args:
            data: JSON data dictionary
            
        Returns:
            True if system data, False if asset data
        """
        # Check for system-level indicators
        if 'Assets' in data and isinstance(data['Assets'], list):
            return True
        
        # Check for asset-level indicators
        if 'components' in data and isinstance(data['components'], list):
            return False
        
        # Default to asset level if unclear
        return False
    
    def _load_asset_data(self, data: Dict[str, Any]) -> Asset:
        """
        Load asset-level data from dictionary
        
        Args:
            data: Asset data dictionary
            
        Returns:
            Asset object
        """
        # Create asset with default values for missing fields
        # Ensure criticality_level is an integer and within valid range
        criticality_level = data.get('criticality_level', 1)
        if isinstance(criticality_level, str):
            try:
                criticality_level = int(criticality_level)
            except ValueError:
                criticality_level = 1
        
        # Clamp criticality level to valid range
        criticality_level = max(1, min(5, int(criticality_level)))
        
        asset = Asset(
            asset_id=str(data.get('asset_id', 'default_asset')),
            name=data.get('name', 'Default Asset'),
            asset_type=data.get('type', ''),
            criticality_level=criticality_level,
            ip_address=data.get('ip_address', '0.0.0.0'),
            mac_address=data.get('mac_address', '00:00:00:00:00:00')
        )
        
        # Process components
        for component_data in data.get('components', []):
            component = self._create_component(component_data)
            asset.add_component(component)
        
        # Set adjacency matrix if present
        adjacency_matrix = data.get('adjacency_matrix', [])
        if adjacency_matrix:
            asset.set_adjacency_matrix(adjacency_matrix)
        
        return asset
    
    def _load_system_data(self, data: Dict[str, Any]) -> System:
        """
        Load system-level data from dictionary
        
        Args:
            data: System data dictionary
            
        Returns:
            System object
        """
        system = System()
        
        # Process assets
        for asset_data in data.get('Assets', []):
            asset = self._load_asset_data(asset_data)
            system.add_asset(asset)
        
        # Process connections
        for connection in data.get('Connections', []):
            if self._validate_connection(connection):
                system.add_connection(connection)
        
        return system
    
    def _create_component(self, component_data: Dict[str, Any]) -> Component:
        """
        Create a component from component data
        
        Args:
            component_data: Component data dictionary
            
        Returns:
            Component object
        """
        component = Component(
            id=component_data.get('id', ''),
            name=component_data.get('name', ''),
            type=component_data.get('type', ''),
            vendor=component_data.get('vendor', ''),
            version=component_data.get('version', ''),
            embedded_in=component_data.get('embedded_in')
        )
        
        # Process vulnerabilities
        for vulnerability_data in component_data.get('vulnerabilities', []):
            vulnerability = self._create_vulnerability(vulnerability_data, component.id)
            component.add_vulnerability(vulnerability)
        
        return component
    
    def _create_vulnerability(self, vulnerability_data: Dict[str, Any], component_id: str) -> Vulnerability:
        """
        Create a vulnerability from vulnerability data
        
        Args:
            vulnerability_data: Vulnerability data dictionary
            component_id: ID of the component this vulnerability belongs to
            
        Returns:
            Vulnerability object
        """
        return Vulnerability(
            cve_id=vulnerability_data.get('cve_id', ''),
            cvss=vulnerability_data.get('cvss', 0.0),
            cvss_v3_vector=vulnerability_data.get('cvssV3Vector', ''),
            scope_changed=vulnerability_data.get('scopeChanged', False),
            likelihood=vulnerability_data.get('likelihood', 0.0),
            impact=vulnerability_data.get('impact', 0.0),
            exploit=vulnerability_data.get('exploit', False),
            epss=vulnerability_data.get('epss', 0.0),
            ransomware=vulnerability_data.get('ransomWare', False),
            component_id=component_id
        )
    
    def _validate_connection(self, connection: Dict[str, Any]) -> bool:
        """
        Validate a network connection
        
        Args:
            connection: Connection data dictionary
            
        Returns:
            True if valid, False otherwise
        """
        required_fields = ['src_ip', 'dst_ip']
        return all(field in connection for field in required_fields)
    
    def save_data(self, data: Union[Asset, System], filename: str) -> None:
        """
        Save data to a JSON file
        
        Args:
            data: Asset or System object to save
            filename: Name of the file to save to
        """
        file_path = self.data_path / filename
        
        # Convert to dictionary
        if isinstance(data, Asset):
            data_dict = data.to_dict()
        elif isinstance(data, System):
            data_dict = data.to_dict()
        else:
            raise ValueError("Data must be Asset or System object")
        
        # Save to file
        with open(file_path, 'w') as f:
            json.dump(data_dict, f, indent=2)
    
    def list_available_files(self) -> Dict[str, list]:
        """
        List available data files, categorized by type
        
        Returns:
            Dictionary with 'asset' and 'system' lists of filenames
        """
        files = {
            'asset': [],
            'system': []
        }
        
        for file_path in self.data_path.glob('*.json'):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                
                if self._is_system_data(data):
                    files['system'].append(file_path.name)
                else:
                    files['asset'].append(file_path.name)
            except (json.JSONDecodeError, KeyError):
                # Skip invalid JSON files
                continue
        
        return files


# Convenience functions for backward compatibility
def load_asset_data(filename: str, data_path: Optional[str] = None) -> Asset:
    """
    Load asset data from file (backward compatibility)
    
    Args:
        filename: Name of the file to load
        data_path: Path to data directory (optional)
        
    Returns:
        Asset object
    """
    if data_path is None:
        # Try to infer from conf.py
        try:
            import conf
            data_path = conf.asset_vul_data_path
        except ImportError:
            raise ValueError("data_path must be provided if conf.py is not available")
    
    loader = DataLoader(data_path)
    result = loader.load_data(filename)
    if not isinstance(result, Asset):
        raise ValueError(f"Expected Asset data, got {type(result).__name__}")
    return result


def load_system_data(filename: str, data_path: Optional[str] = None) -> System:
    """
    Load system data from file (backward compatibility)
    
    Args:
        filename: Name of the file to load
        data_path: Path to data directory (optional)
        
    Returns:
        System object
    """
    if data_path is None:
        # Try to infer from conf.py
        try:
            import conf
            data_path = conf.asset_vul_data_path
        except ImportError:
            raise ValueError("data_path must be provided if conf.py is not available")
    
    loader = DataLoader(data_path)
    result = loader.load_data(filename)
    if not isinstance(result, System):
        raise ValueError(f"Expected System data, got {type(result).__name__}")
    return result 