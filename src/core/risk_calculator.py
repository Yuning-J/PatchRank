"""
Simplified risk calculation module for PatchRank
Contains only basic/common functions and asset-level calculations
System-level calculations are in:
- risk_calculator_system.py (unified system-level calculator)
"""

import torch
import numpy as np
import networkx as nx
import logging
from typing import List, Dict, Tuple, Optional, Union, Any

logger = logging.getLogger(__name__)

from .models import Vulnerability, Asset, System, AnalysisLevel
from .mitigation_factor import MitigationFactorCalculator, MitigationAwareIndirectRisk
from .exploit_score import ExploitScoreCalculator

class RiskCalculator:
    """Basic risk calculator for asset-level analysis and common functions"""
    
    def __init__(self, mitigation_config_path: Optional[str] = None):
        """Initialize the risk calculator with default parameters"""
        # CVSS severity weights
        self.cvss_weights = {'C': 0.4, 'H': 0.3, 'M': 0.2, 'L': 0.1}
        
        # Initialize mitigation-aware risk calculation
        self.mitigation_calc = MitigationFactorCalculator(mitigation_config_path)
        self.mitigation_risk_calc = MitigationAwareIndirectRisk(self.mitigation_calc)
        
        # Initialize continuous exploit score calculator
        self.exploit_score_calc = ExploitScoreCalculator()
        
        # CVSS severity scales
        self.severity_scales = {
            'C': (9.0, 10.0),  # Critical
            'H': (7.0, 8.9),   # High
            'M': (4.0, 6.9),   # Medium
            'L': (0.1, 3.9)    # Low
        }
        
        # Exploit likelihood weights
        self.exploit_weights = {
            'cvss': 0.3,
            'epss': 0.4,
            'exploit': 0.3
        }
        
        # Propagation likelihood weights
        self.propagation_weights = {
            'scope_change': 0.5,
            'ransomware': 0.5
        }
        
        # Business criticality mapping
        self.criticality_mapping = {
            1: 0.1,  # Very Low
            2: 0.3,  # Low
            3: 0.5,  # Medium
            4: 0.7,  # High
            5: 0.9,  # Very High
            6: 1.0   # Critical
        }

    def calculate_vulnerability_risk(self, vulnerability: Vulnerability) -> float:
        """
        Calculate risk score for a single vulnerability
        
        Args:
            vulnerability: Vulnerability object
            
        Returns:
            Risk score (0-10)
        """
        # Base risk from CVSS
        base_risk = vulnerability.cvss
        
        # Exploit likelihood factor
        exploit_likelihood = self.calculate_exploit_likelihood(vulnerability)
        
        # Propagation likelihood factor  
        propagation_likelihood = self.calculate_propagation_likelihood(vulnerability)
        
        # Combined risk score
        risk_score = base_risk * exploit_likelihood * (1 + propagation_likelihood)
        
        return min(10.0, max(0.0, risk_score))
        
    def calculate_exploit_likelihood(self, vulnerability: Vulnerability, asset: Dict[str, Any] = None) -> float:
        """
        Calculate exploit likelihood for a vulnerability
        
        Args:
            vulnerability: Vulnerability object
            asset: Asset context (optional)
            
        Returns:
            Exploit likelihood (0-1)
        """
        try:
            # Use the continuous exploit score calculator
            # Convert vulnerability object to dictionary for the exploit score calculator
            vuln_dict = {
                'exploit': getattr(vulnerability, 'exploit', False),
                'epss_score': getattr(vulnerability, 'epss', 0.0),
                'cvssV3Vector': getattr(vulnerability, 'cvssV3Vector', '')
            }
            exploit_score = self.exploit_score_calc.calculate_exploit_score(vulnerability.cve_id, asset or {}, vuln_dict)
            
            # Debug output
            logger.debug(f"{vulnerability.cve_id} - exploit_score: {exploit_score}")
            
            # Exploit score is already in 0-1 range, no need to normalize
            return exploit_score
            
        except Exception as e:
            logger.warning(f"Could not calculate exploit likelihood for {vulnerability.cve_id}: {e}")
            # Fallback to basic calculation
            cvss_factor = min(1.0, vulnerability.cvss / 10.0)
            epss_factor = vulnerability.epss if hasattr(vulnerability, 'epss') else 0.5
            exploit_factor = vulnerability.exploit if hasattr(vulnerability, 'exploit') else 0.5
            
            # Weighted combination
            likelihood = (
                self.exploit_weights['cvss'] * cvss_factor +
                self.exploit_weights['epss'] * epss_factor +
                self.exploit_weights['exploit'] * exploit_factor
            )
            
            return min(1.0, max(0.0, likelihood))
    
    def calculate_propagation_likelihood(self, vulnerability: Vulnerability) -> float:
        """
        Calculate propagation likelihood for a vulnerability
        
        Args:
            vulnerability: Vulnerability object
            
        Returns:
            Propagation likelihood (0-1)
        """
        try:
            # Check if scope can be changed
            scope_change = getattr(vulnerability, 'scope_changed', False)
            scope_factor = 1.0 if scope_change else 0.0
            
            # Check if ransomware can be used
            ransomware = getattr(vulnerability, 'ransomware', False)
            ransomware_factor = 1.0 if ransomware else 0.0
            
            # Weighted combination
            propagation_likelihood = (
                self.propagation_weights['scope_change'] * scope_factor +
                self.propagation_weights['ransomware'] * ransomware_factor
            )
            
            return min(1.0, max(0.0, propagation_likelihood))
                    
        except Exception as e:
            logger.warning(f"Could not calculate propagation likelihood for {vulnerability.cve_id}: {e}")
            return 0.1  # Default low propagation
    
    def calculate_direct_risk(self, exploit_likelihood: float, impact: float, centrality: float) -> float:
        """
        Calculate direct risk for a vulnerability
        
        Args:
            exploit_likelihood: Exploit likelihood (0-1)
            impact: Impact score (0-1)
            centrality: Asset centrality (0-1)
            
        Returns:
            Direct risk score
        """
        # Direct risk = exploit likelihood × impact × centrality
        direct_risk = exploit_likelihood * impact * centrality
        
        return direct_risk
    
    def calculate_asset_risk(self, asset: Asset) -> float:
        """
        Calculate total risk for an asset using BFS propagation (like old system)
        
        Args:
            asset: Asset object
            
        Returns:
            Total asset risk
        """
        try:
            logger.debug(f"Starting asset risk calculation for asset type: {type(asset)}")
            logger.debug(f"Asset has {len(asset.components)} components")
            
            # Generate sub-graph first (like old system)
            from src.core.graph_processor import GraphProcessor
            graph_processor = GraphProcessor()
            G, data_obj = graph_processor.generate_sub_graph(asset)
            
            logger.debug(f"Generated graph with {len(G.nodes)} nodes")
            logger.debug(f"Data object shape: {data_obj.x.shape}")
            
            # Use the old logic for asset risk calculation
            from src.old.risk_calculation import calculate_asset_risk as old_calculate_asset_risk
            _, _, component_risks, total_propagated_risk = old_calculate_asset_risk(asset, data_obj)
            
            logger.debug(f"Total propagated risk: {total_propagated_risk}")
            return total_propagated_risk
            
        except Exception as e:
            logger.debug(f"BFS calculation failed: {e}, using fallback")
            # Fallback to simple calculation
            total_risk = 0.0
            
            for component in asset.components:
                for vulnerability in component.vulnerabilities:
                    # Calculate exploit likelihood
                    exploit_likelihood = self.calculate_exploit_likelihood(vulnerability, asset.__dict__)
                    
                    # Calculate direct risk
                    impact = vulnerability.impact if hasattr(vulnerability, 'impact') else 0.5
                    centrality = self.calculate_asset_centrality_risk(asset)
                    direct_risk = self.calculate_direct_risk(exploit_likelihood, impact, centrality)
                    
                    # Calculate propagation likelihood
                    propagation_likelihood = self.calculate_propagation_likelihood(vulnerability)
                    
                    # Calculate total risk for this vulnerability
                    vuln_risk = direct_risk * (1 + propagation_likelihood)
                    total_risk += vuln_risk
            
            return total_risk

    def calculate_cvs(self, asset: Asset) -> float:
        """
        Calculate Component Vulnerability Score (CVS) for an asset
        Using the old system's severity-weighted approach
        
        Args:
            asset: Asset object
            
        Returns:
            CVS score
        """
        total_cvs = 0.0
        total_components = len(asset.components)
        
        if total_components == 0:
            return 0.0
        
        for component in asset.components:
            # Use the component-level CVS calculation
            component_cvs = self.calculate_component_cvs(component.vulnerabilities)
            total_cvs += component_cvs
        
        # Overall CVS for the asset
        overall_cvs = total_cvs / total_components
        
        return overall_cvs

    def calculate_component_cvs(self, vulnerabilities: List[Vulnerability]) -> float:
        """
        Calculate Component Vulnerability Score (CVS) for a list of vulnerabilities (component-level)
        Using the old system's severity-weighted approach
        
        Args:
            vulnerabilities: List of Vulnerability objects
            
        Returns:
            CVS score for the component
        """
        if not vulnerabilities:
            return 0.0
        
        # Use the old system's severity-weighted approach
        weights = {'C': 0.4, 'H': 0.3, 'M': 0.2, 'L': 0.1}
        severity_scales = {'C': (9.0, 10.0), 'H': (7.0, 8.9), 'M': (4.0, 6.9), 'L': (0.1, 3.9)}
        sum_severity = {'C': 0, 'H': 0, 'M': 0, 'L': 0}
        count_severity = {'C': 0, 'H': 0, 'M': 0, 'L': 0}

        for vul in vulnerabilities:
            cvss = vul.cvss
            for scale, (low, high) in severity_scales.items():
                if low <= cvss <= high:
                    sum_severity[scale] += cvss
                    count_severity[scale] += 1
                    break

        weighted_sum = sum(weights[scale] * sum_severity[scale] for scale in severity_scales.keys())
        weighted_average = weighted_sum / sum(weights[scale] for scale in severity_scales.keys())
        total_count = sum(count_severity.values())

        # Incorporate the number of vulnerabilities into the CVS calculation with a smaller factor
        vulnerability_factor = 1 + 0 * total_count

        return weighted_average * vulnerability_factor if total_count > 0 else 0

    def calculate_asset_centrality_risk(self, asset: Asset) -> float:
        """
        Calculate centrality-based risk for an asset
        
        Args:
            asset: Asset object
            
        Returns:
            Centrality risk score (0-1)
        """
        try:
            # Use business criticality if available
            if hasattr(asset, 'business_criticality') and asset.business_criticality:
                criticality = asset.business_criticality
                return self.criticality_mapping.get(criticality, 0.5)
            
            # Use final criticality if available
            if hasattr(asset, 'final_criticality') and asset.final_criticality:
                criticality = asset.final_criticality
                return self.criticality_mapping.get(criticality, 0.5)
            
            # Default centrality
            return 0.5
        except Exception as e:
            logger.warning(f"Could not calculate centrality risk for asset {asset.asset_id}: {e}")
            return 0.5

    def prepare_assets_for_system_calculation(self, data: System, graph_processor, main_graph):
        """
        Prepare assets for system-level calculation (basic version)
        
        Args:
            data: System data
            graph_processor: Graph processor instance
            main_graph: System network graph
        """
        logger.info("Preparing assets for system calculation (basic version)")
        
        for asset in data.assets:
            try:
                # Calculate basic asset risk
                asset.total_propagated_risk = self.calculate_asset_risk(asset)
                logger.debug(f"Asset {asset.asset_id}: total_propagated_risk = {asset.total_propagated_risk:.3f}")
                        
            except Exception as e:
                logger.warning(f"Could not prepare asset {asset.asset_id}: {e}")
                asset.total_propagated_risk = 0.0

    def normalize_business_criticality_rule_based(self, criticality_level: int) -> float:
        """
        Apply rule-based normalization for business criticality (like old system)
        
        Args:
            criticality_level: Original business criticality level (1-6)
            
        Returns:
            Normalized business criticality (0-1)
        """
        rule_based_mapping = {
            1: 0.1,  # Very Low
            2: 0.3,  # Low  
            3: 0.5,  # Medium
            4: 0.7,  # High
            5: 0.9,  # Very High
            6: 1.0   # Critical
        }
        return rule_based_mapping.get(criticality_level, 0.1)

    def recalculate_asset_criticality(self, assets: List[Asset], asset_centrality: Dict[str, float]) -> Tuple[Dict[str, float], Dict[str, float]]:
        """
        Recalculate asset criticality based on centrality (like old system)
        
        Args:
            assets: List of assets
            asset_centrality: Asset centrality data
            
        Returns:
            Tuple of (updated_criticality, final_criticality)
        """
        updated_criticality = {}
        final_criticality = {}
        
        for asset in assets:
            try:
                asset_id = asset.asset_id
                business_criticality = asset.criticality_level
                normalized_centrality = asset_centrality.get(asset_id, 0.0)

                # Apply rule-based normalization for business criticality
                normalized_business_criticality = self.normalize_business_criticality_rule_based(business_criticality)

                # Combine normalized values using a weighted sum (like old system)
                combined_criticality = 0.4 * normalized_business_criticality + 0.6 * normalized_centrality
                updated_criticality[asset_id] = combined_criticality
                
                # Convert to integer final criticality between 0 and 10 (like old system)
                integer_final_criticality = int(combined_criticality * 10)
                final_criticality[asset_id] = integer_final_criticality
                
                print(f"  Asset {asset_id}: business_criticality={business_criticality}, normalized_business={normalized_business_criticality:.3f}, centrality={normalized_centrality:.3f}, combined={combined_criticality:.3f}, final_criticality={integer_final_criticality}")
                        
            except Exception as e:
                logger.warning(f"Could not recalculate criticality for asset {asset.asset_id}: {e}")
                updated_criticality[asset.asset_id] = 0.5
                final_criticality[asset.asset_id] = 5
        
        return updated_criticality, final_criticality

    def calculate_centrality(self, G: nx.DiGraph, centrality_type='network'):
        """
        Calculate centrality with different scopes
        
        Args:
            G: Dependency graph
            centrality_type: 
                - 'structural': Only intra-asset dependencies (same for NP1/NP2)
                - 'network': Full graph including inter-dependencies (different for NP1/NP2)
                - 'hybrid': Return both structural and network centrality
            
        Returns:
            For 'structural' or 'network': (centrality_tensor, centrality_dict)
            For 'hybrid': {'structural': (tensor, dict), 'network': (tensor, dict)}
        """
        if centrality_type == 'structural':
            # Build graph with ONLY intra-asset dependencies
            G_structural = nx.DiGraph()
            for node in G.nodes():
                G_structural.add_node(node)
            
            # Only add edges within same asset
            for (u, v) in G.edges():
                asset_u = u.split('_')[0]  # Extract asset ID
                asset_v = v.split('_')[0]
                if asset_u == asset_v:
                    G_structural.add_edge(u, v, **G[u][v])  # Copy edge attributes
            
            # Calculate centrality on structural graph
            return self._calculate_centrality_metrics(G_structural)
        
        elif centrality_type == 'network':
            # Use full graph (current implementation)
            return self._calculate_centrality_metrics(G)
        
        elif centrality_type == 'hybrid':
            # Return both for different uses
            return {
                'structural': self.calculate_centrality(G, 'structural'),
                'network': self.calculate_centrality(G, 'network')
            }
        
        else:
            raise ValueError(f"Unknown centrality_type: {centrality_type}")
    
    def _calculate_centrality_metrics(self, G: nx.DiGraph):
        """Calculate centrality metrics for a given graph"""
        if len(G) == 0:
            raise ValueError("Graph is empty. Cannot calculate centrality.")
        
        if not G.is_directed():
            G = G.to_directed()
        
        in_degree_centrality = nx.in_degree_centrality(G)
        out_degree_centrality = nx.out_degree_centrality(G)
        betweenness_centrality = nx.betweenness_centrality(G, normalized=True, endpoints=True)
        pagerank = nx.pagerank(G, alpha=0.85)
        
        centrality = {}
        for node in G.nodes():
            centrality[node] = (
                in_degree_centrality[node] +
                out_degree_centrality[node] +
                betweenness_centrality[node] +
                pagerank[node]
            ) / 4
        
        # Normalize by maximum centrality value
        if centrality:
            max_centrality = max(centrality.values())
            if max_centrality > 0:
                for node in centrality:
                    centrality[node] /= max_centrality
        
        centrality_tensor = torch.tensor([centrality[node] for node in G.nodes()], dtype=torch.float32).unsqueeze(1)
        return centrality_tensor, centrality
    



 

 