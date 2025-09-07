"""
Unified dependency calculation module for PatchRank
Handles inter-host and intra-host dependency analysis
"""

import networkx as nx
import json
import os
from typing import Dict, Any, List, Tuple, Optional

from .models import System, Asset, DependencyType
from .risk_calculator import RiskCalculator


class DependencyCalculator:
    """Unified dependency calculator for system-level analysis"""
    
    def __init__(self, asset_data_path: str):
        """
        Initialize the dependency calculator
        
        Args:
            asset_data_path: Path to asset data directory
        """
        self.asset_data_path = asset_data_path
        self.risk_calculator = RiskCalculator()
        
        # Dependency weights for different types
        self.dependency_weights = {
            DependencyType.EMBEDDING: 2,      # ER
            DependencyType.INTER_HOST: 1,     # IR
            DependencyType.DATA_RELATED: 1,   # DR
            DependencyType.SERVICE_RELATED: 1, # SR
            DependencyType.NETWORK: 2,        # NR
            DependencyType.SECURITY_CONTROL: 1 # SCR
        }
    
    def generate_dependence(self, data: System, scenario_id: str) -> Dict[str, Dict[str, float]]:
        """
        Generate dependency analysis for a system
        
        Args:
            data: System object containing assets
            scenario_id: Scenario identifier for loading dependencies
            
        Returns:
            Dictionary containing asset and component centrality data
        """
        # Load inter-host dependencies
        inter_dependencies = self._load_inter_dependencies(scenario_id)
        
        # Create dependency graph
        G = self._build_dependency_graph(data, inter_dependencies)
        
        # Calculate both structural and network centrality
        centrality_results = self.risk_calculator.calculate_centrality(G, 'hybrid')
        
        # Extract structural and network centrality
        structural_tensor, structural_centrality = centrality_results['structural']
        network_tensor, network_centrality = centrality_results['network']
        
        # Convert to dictionaries with string keys
        structural_centrality_dict = {
            str(node): centrality for node, centrality in structural_centrality.items()
        }
        network_centrality_dict = {
            str(node): centrality for node, centrality in network_centrality.items()
        }
        
        # Aggregate centrality to compute asset centrality (use network to capture topology differences)
        asset_centrality = self._calculate_asset_centrality(data, network_centrality_dict)
        
        return {
            'asset_centrality': asset_centrality,
            'component_centrality': {
                'structural': structural_centrality_dict,
                'network': network_centrality_dict
            }
        }
    
    def _load_inter_dependencies(self, scenario_id: str) -> List[Tuple[str, str, str]]:
        """
        Load inter-host dependencies from JSON file
        
        Args:
            scenario_id: Scenario identifier
            
        Returns:
            List of (source, destination, dependency_type) tuples
        """
        dependencies_file = os.path.join(self.asset_data_path, 'inter_dependencies.json')
        
        if not os.path.exists(dependencies_file):
            print(f"Warning: Dependencies file not found: {dependencies_file}")
            return []
        
        try:
            with open(dependencies_file, 'r') as f:
                dependence_data = json.load(f)
            
            # Load inter-host dependencies for the specific scenario
            inter_dependencies_key = f'inter_dependencies_{scenario_id}'
            inter_dependencies = dependence_data.get(inter_dependencies_key, [])
            
            return inter_dependencies
            
        except (json.JSONDecodeError, KeyError) as e:
            print(f"Error loading dependencies for scenario {scenario_id}: {e}")
            return []
    
    def _build_dependency_graph(self, data: System, 
                              inter_dependencies: List[Tuple[str, str, str]]) -> nx.DiGraph:
        """
        Build dependency graph from system data and inter-dependencies
        
        Args:
            data: System object
            inter_dependencies: List of inter-host dependencies
            
        Returns:
            NetworkX directed graph
        """
        G = nx.DiGraph()
        
        # Add nodes and intra-host dependencies from adjacency matrices
        for asset in data.assets:
            asset_id = asset.asset_id
            components = asset.components
            matrix = asset.adjacency_matrix
            
            # Add nodes for each component
            for component in components:
                component_name = f"A{asset_id}_{component.name}"
                G.add_node(component_name)
            
            # Add edges based on adjacency matrix
            for i, row in enumerate(matrix):
                for j, weight in enumerate(row):
                    if weight > 0:
                        # Determine dependency type based on weight
                        if weight == 2:
                            dep_type = DependencyType.EMBEDDING
                        elif weight == 1:
                            dep_type = DependencyType.SERVICE_RELATED
                        else:
                            dep_type = DependencyType.SERVICE_RELATED
                        
                        G.add_edge(
                            f"A{asset_id}_{components[i].name}",
                            f"A{asset_id}_{components[j].name}",
                            weight=weight,
                            dep_type=dep_type.value
                        )
        
        # Add inter-host dependencies
        for src, dst, dep_type in inter_dependencies:
            weight = self.dependency_weights.get(DependencyType(dep_type), 1)
            G.add_edge(src, dst, weight=weight, dep_type=dep_type)
        
        return G
    
    def _calculate_asset_centrality(self, data: System, 
                                  component_centrality: Dict[str, float]) -> Dict[str, float]:
        """
        Calculate asset centrality by aggregating component centrality
        
        Args:
            data: System object
            component_centrality: Component centrality dictionary
            
        Returns:
            Asset centrality dictionary
        """
        asset_centrality = {}
        
        # Check if we have meaningful component centrality data
        max_comp_centrality = max(component_centrality.values()) if component_centrality else 0.0
        has_meaningful_centrality = max_comp_centrality > 0.01
        
        for asset in data.assets:
            asset_id = str(asset.asset_id)  # Ensure string key
            components = asset.components
            
            if has_meaningful_centrality and components:
                # FOLLOW OLD LOGIC EXACTLY: Use AVERAGE centrality for components in this asset
                centrality_values = [
                    component_centrality.get(f"A{asset_id}_{comp.name}", 0)
                    for comp in components
                ]
                asset_centrality[asset_id] = sum(centrality_values) / len(components) if centrality_values else 0
            else:
                # Fallback based on asset business criticality when centrality fails
                # Normalize business criticality to 0-1 range
                normalized_criticality = (asset.criticality_level - 1) / 4.0  # 1-5 → 0-1
                asset_centrality[asset_id] = normalized_criticality
                if not has_meaningful_centrality:
                    print(f"Warning: Using business criticality fallback for asset centrality {asset_id}")
        
        return asset_centrality
    
    def analyze_dependency_impact(self, data: System, 
                                component_centrality: Dict[str, float]) -> Dict[str, Any]:
        """
        Analyze the impact of dependencies on system risk
        
        Args:
            data: System object
            component_centrality: Component centrality dictionary
            
        Returns:
            Dependency impact analysis
        """
        analysis = {
            'high_impact_components': [],
            'dependency_chains': [],
            'risk_propagation_paths': []
        }
        
        # Identify high-impact components (centrality > 0.7)
        for component_name, centrality in component_centrality.items():
            if centrality > 0.7:
                analysis['high_impact_components'].append({
                    'component': component_name,
                    'centrality': centrality
                })
        
        # Analyze dependency chains
        for asset in data.assets:
            asset_id = asset.asset_id
            
            # Find components with high centrality in this asset
            high_centrality_components = [
                comp for comp in asset.components
                if component_centrality.get(f"A{asset_id}_{comp.name}", 0) > 0.5
            ]
            
            if high_centrality_components:
                analysis['dependency_chains'].append({
                    'asset': asset.name,
                    'asset_id': asset_id,
                    'high_centrality_components': [
                        comp.name for comp in high_centrality_components
                    ]
                })
        
        return analysis
    
    def get_dependency_statistics(self, data: System) -> Dict[str, Any]:
        """
        Get statistics about dependencies in the system
        
        Args:
            data: System object
            
        Returns:
            Dependency statistics
        """
        stats = {
            'total_assets': len(data.assets),
            'total_components': sum(len(asset.components) for asset in data.assets),
            'total_vulnerabilities': sum(
                asset.get_vulnerability_count() for asset in data.assets
            ),
            'assets_by_criticality': {},
            'components_by_type': {}
        }
        
        # Count assets by criticality level
        for asset in data.assets:
            criticality = asset.criticality_level
            stats['assets_by_criticality'][criticality] = (
                stats['assets_by_criticality'].get(criticality, 0) + 1
            )
        
        # Count components by type
        for asset in data.assets:
            for component in asset.components:
                comp_type = component.type or 'Unknown'
                stats['components_by_type'][comp_type] = (
                    stats['components_by_type'].get(comp_type, 0) + 1
                )
        
        return stats


# Convenience function for backward compatibility
def generate_dependence(data: System, scenario_id: str, asset_data_path: Optional[str] = None) -> Dict[str, Dict[str, float]]:
    """
    Generate dependency analysis (backward compatibility)
    
    Args:
        data: System object
        scenario_id: Scenario identifier
        asset_data_path: Path to asset data directory (optional)
        
    Returns:
        Dictionary containing asset and component centrality data
    """
    if asset_data_path is None:
        # Try to infer from conf.py
        try:
            import conf
            asset_data_path = conf.asset_data_path
        except ImportError:
            raise ValueError("asset_data_path must be provided if conf.py is not available")
    
    calculator = DependencyCalculator(asset_data_path)
    return calculator.generate_dependence(data, scenario_id) 