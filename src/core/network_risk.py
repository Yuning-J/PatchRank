"""
Network Risk Calculator for Multi-Path Risk Analysis
Implements Task 1.3d: Network risk calculation using k-shortest paths
Equation: R_network = Σ_assets Σ_P∈Paths Prob(P) * Risk(P)
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
import networkx as nx
from dataclasses import dataclass

from .graph_utils import GraphUtils, PathInfo, create_attack_graph_with_verticals
try:
    from src.conf import get_config
except ImportError:
    try:
        from conf import get_config
    except ImportError:
        # Fallback for when running from project root
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
        from conf import get_config

logger = logging.getLogger(__name__)


@dataclass
class NetworkRiskResult:
    """Result of network risk calculation"""
    total_network_risk: float
    asset_risks: Dict[str, float]
    path_contributions: List[Dict[str, Any]]
    k_paths_used: int
    baseline_shortest_risk: float
    performance_metrics: Dict[str, Any]


class NetworkRiskCalculator:
    """Calculate network risk using k-shortest paths algorithm"""
    
    def __init__(self, graph: nx.DiGraph = None):
        """
        Initialize network risk calculator
        
        Args:
            graph: Attack graph (NetworkX DiGraph)
        """
        self.config = get_config()
        self.graph_utils = GraphUtils()
        self.graph = None  # Initialize graph attribute
        
        if graph:
            self.set_graph(graph)
    
    def set_graph(self, graph: nx.DiGraph) -> None:
        """Set the attack graph for analysis"""
        self.graph = graph
        self.graph_utils.set_graph(graph)
        logger.info(f"Set graph with {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
    
    def calculate_network_risk(self, 
                             vulnerable_assets: List[str],
                             source_assets: List[str] = None,
                             k: int = None) -> NetworkRiskResult:
        """
        Calculate network risk using k-shortest paths
        
        Args:
            vulnerable_assets: List of assets with vulnerabilities 
            source_assets: List of potential attack sources (default: all assets)
            k: Number of shortest paths (default: from config)
            
        Returns:
            NetworkRiskResult with comprehensive risk analysis
        """
        if not self.graph:
            raise ValueError("Graph not set. Call set_graph() first.")
        
        # Use config value if k not specified
        if k is None:
            k = self.config.risk_calculation.k_shortest_paths
            
        if source_assets is None:
            source_assets = list(self.graph.nodes)
        
        logger.info(f"Calculating network risk for {len(vulnerable_assets)} vulnerable assets "
                   f"from {len(source_assets)} sources using {k}-shortest paths")
        
        # Initialize result tracking
        total_risk = 0.0
        asset_risks = {}
        path_contributions = []
        
        # Calculate baseline with shortest path for comparison
        baseline_risk = self._calculate_baseline_shortest_path_risk(vulnerable_assets, source_assets)
        
        # Calculate k-shortest paths risk for each vulnerable asset
        for target_asset in vulnerable_assets:
            if target_asset not in self.graph.nodes:
                logger.warning(f"Target asset {target_asset} not in graph")
                continue
                
            asset_risk = 0.0
            
            # Find paths from each source to this target
            for source_asset in source_assets:
                if source_asset == target_asset:
                    continue
                    
                if source_asset not in self.graph.nodes:
                    continue
                
                # Get k-shortest paths
                paths = self.graph_utils.k_shortest_paths(source_asset, target_asset, k)
                
                # Calculate risk contribution from each path
                for path_info in paths:
                    # Network risk per path: Prob(P) * Risk(P)
                    risk_contribution = path_info.probability * path_info.risk
                    asset_risk += risk_contribution
                    
                    # Track detailed path information
                    path_contribution = {
                        'source': source_asset,
                        'target': target_asset,
                        'path': path_info.path,
                        'path_length': len(path_info.path) - 1,  # Number of edges
                        'probability': path_info.probability,
                        'risk': path_info.risk,
                        'contribution': risk_contribution,
                        'edges': path_info.edges
                    }
                    path_contributions.append(path_contribution)
            
            asset_risks[target_asset] = asset_risk
            total_risk += asset_risk
            
            logger.debug(f"Asset {target_asset} network risk: {asset_risk:.4f}")
        
        # Calculate performance metrics
        performance_metrics = self._calculate_performance_metrics(
            len(vulnerable_assets), len(source_assets), k, len(path_contributions)
        )
        
        result = NetworkRiskResult(
            total_network_risk=total_risk,
            asset_risks=asset_risks,
            path_contributions=path_contributions,
            k_paths_used=k,
            baseline_shortest_risk=baseline_risk,
            performance_metrics=performance_metrics
        )
        
        logger.info(f"Network risk calculation complete: total={total_risk:.4f}, "
                   f"baseline={baseline_risk:.4f}, paths={len(path_contributions)}")
        
        return result
    
    def calculate_risk_with_mitigation_scenarios(self,
                                               vulnerable_assets: List[str],
                                               mitigation_scenarios: List[Dict[str, Any]],
                                               k: int = None) -> Dict[str, NetworkRiskResult]:
        """
        Calculate network risk under different mitigation scenarios
        
        Args:
            vulnerable_assets: List of vulnerable assets
            mitigation_scenarios: List of mitigation configurations
            k: Number of shortest paths
            
        Returns:
            Dictionary mapping scenario names to NetworkRiskResult
        """
        if k is None:
            k = self.config.risk_calculation.k_shortest_paths
            
        results = {}
        
        # Store original graph state
        original_edges = {}
        for edge in self.graph.edges(data=True):
            original_edges[(edge[0], edge[1])] = edge[2].copy()
        
        for scenario in mitigation_scenarios:
            scenario_name = scenario.get('name', 'unnamed_scenario')
            
            # Apply mitigation scenario to graph
            self._apply_mitigation_scenario(scenario)
            
            # Calculate risk under this scenario
            result = self.calculate_network_risk(vulnerable_assets, k=k)
            results[scenario_name] = result
            
            # Restore original graph state
            self._restore_graph_state(original_edges)
            
            logger.info(f"Scenario '{scenario_name}' network risk: {result.total_network_risk:.4f}")
        
        return results
    
    def compare_k_values(self,
                        vulnerable_assets: List[str],
                        k_values: List[int] = None) -> Dict[int, NetworkRiskResult]:
        """
        Compare network risk calculations with different k values
        
        Args:
            vulnerable_assets: List of vulnerable assets
            k_values: List of k values to test (default: [1,3,5])
            
        Returns:
            Dictionary mapping k values to NetworkRiskResult
        """
        if k_values is None:
            k_values = [1, 3, 5]
            
        results = {}
        
        for k in k_values:
            result = self.calculate_network_risk(vulnerable_assets, k=k)
            results[k] = result
            
            logger.info(f"k={k} network risk: {result.total_network_risk:.4f} "
                       f"(paths: {len(result.path_contributions)})")
        
        return results
    
    def _calculate_baseline_shortest_path_risk(self,
                                             vulnerable_assets: List[str],
                                             source_assets: List[str]) -> float:
        """Calculate baseline risk using only shortest paths (k=1)"""
        baseline_risk = 0.0
        
        for target in vulnerable_assets:
            for source in source_assets:
                if source == target or source not in self.graph.nodes or target not in self.graph.nodes:
                    continue
                    
                try:
                    # Get single shortest path
                    shortest_path = nx.shortest_path(self.graph, source, target, weight='weight')
                    edges = [(shortest_path[i], shortest_path[i+1]) for i in range(len(shortest_path)-1)]
                    
                    # Calculate probability and risk
                    probability = self.graph_utils._calculate_path_probability(edges)
                    risk = self.graph_utils._calculate_path_risk(edges, probability)
                    
                    baseline_risk += probability * risk
                    
                except nx.NetworkXNoPath:
                    continue
        
        return baseline_risk
    
    def _calculate_performance_metrics(self,
                                     num_targets: int,
                                     num_sources: int,
                                     k: int,
                                     total_paths: int) -> Dict[str, Any]:
        """Calculate performance metrics for the analysis"""
        return {
            'num_target_assets': num_targets,
            'num_source_assets': num_sources,
            'k_paths_per_pair': k,
            'total_paths_analyzed': total_paths,
            'avg_paths_per_target': total_paths / max(num_targets, 1),
            'theoretical_max_paths': num_targets * num_sources * k
        }
    
    def _apply_mitigation_scenario(self, scenario: Dict[str, Any]) -> None:
        """Apply mitigation scenario to graph edges"""
        mitigations = scenario.get('mitigations', {})
        
        for edge in self.graph.edges(data=True):
            edge_data = edge[2]
            
            # Apply global mitigation factor if specified
            if 'global_mitigation_factor' in mitigations:
                current_mf = edge_data.get('mitigation_factor', 1.0)
                edge_data['mitigation_factor'] = current_mf * mitigations['global_mitigation_factor']
            
            # Apply specific edge mitigations
            edge_id = f"{edge[0]}_{edge[1]}"
            if edge_id in mitigations:
                edge_mf = mitigations[edge_id]
                edge_data['mitigation_factor'] = edge_mf
    
    def _restore_graph_state(self, original_edges: Dict[Tuple[str, str], Dict[str, Any]]) -> None:
        """Restore graph to original state"""
        for edge, data in original_edges.items():
            if self.graph.has_edge(*edge):
                self.graph[edge[0]][edge[1]].update(data)


def integrate_with_risk_calculator(risk_calculator, vulnerable_assets: List[str]) -> float:
    """
    Integrate network risk calculation with existing RiskCalculator
    
    Args:
        risk_calculator: Instance of RiskCalculator
        vulnerable_assets: List of vulnerable assets
        
    Returns:
        Total network risk contribution
    """
    if not hasattr(risk_calculator, 'graph') or risk_calculator.graph is None:
        logger.warning("RiskCalculator has no graph. Network risk = 0.0")
        return 0.0
    
    # Create network risk calculator
    network_calc = NetworkRiskCalculator(risk_calculator.graph)
    
    # Calculate network risk
    result = network_calc.calculate_network_risk(vulnerable_assets)
    
    logger.info(f"Integrated network risk: {result.total_network_risk:.4f}")
    return result.total_network_risk


# Utility function for creating test scenarios
def create_test_scenario(num_assets: int = 10, connectivity: float = 0.3) -> nx.DiGraph:
    """
    Create a test attack graph for network risk analysis
    
    Args:
        num_assets: Number of assets to create
        connectivity: Edge connectivity probability [0,1]
        
    Returns:
        Test attack graph
    """
    import random
    
    # Create test assets
    assets = []
    asset_types = ['host', 'server', 'hypervisor', 'gpu', 'switch']
    
    for i in range(num_assets):
        asset_type = random.choice(asset_types)
        connections = []
        
        # Create some random connections
        for j in range(num_assets):
            if i != j and random.random() < connectivity:
                connections.append(f"asset_{j}")
        
        asset = {
            'id': f'asset_{i}',
            'type': asset_type,
            'subnet': f'subnet_{i//3}',  # Group assets into subnets
            'host': f'host_{i//2}' if asset_type == 'gpu' else None,
            'connections': connections,
            'internet_facing': i < 2,  # First 2 assets are internet-facing
            'vulnerabilities': [f'CVE-2023-{1000+i}'] if i % 3 == 0 else []
        }
        assets.append(asset)
    
    return create_attack_graph_with_verticals(assets)