"""
Unified risk calculation module for PatchRank
Consolidates all risk calculation functions with improved architecture
"""

import torch
import numpy as np
import networkx as nx
from typing import List, Dict, Tuple, Optional, Union, Any

from .models import Vulnerability, Asset, System, AnalysisLevel


class RiskCalculator:
    """Unified risk calculator for both asset and system level analysis"""
    
    def __init__(self):
        """Initialize the risk calculator with default parameters"""
        # CVSS severity weights
        self.cvss_weights = {'C': 0.4, 'H': 0.3, 'M': 0.2, 'L': 0.1}
        
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
        
        # Combine factors
        risk_multiplier = 1.0 + (exploit_likelihood * 0.3) + (propagation_likelihood * 0.2)
        
        # Calculate final risk
        final_risk = base_risk * risk_multiplier
        
        # Ensure risk is within bounds
        return min(final_risk, 10.0)

    def calculate_component_risk(self, component) -> float:
        """
        Calculate risk score for a component based on its vulnerabilities
        
        Args:
            component: Component object
            
        Returns:
            Component risk score (0-10)
        """
        if not component.vulnerabilities:
            return 0.0
        
        # Calculate CVS (Component Vulnerability Score)
        cvs = self.calculate_cvs(component.vulnerabilities)
        
        # Factor in vulnerability count
        vuln_count_factor = 1.0 + (len(component.vulnerabilities) * 0.1)
        
        # Calculate component risk
        component_risk = cvs * vuln_count_factor
        
        # Ensure risk is within bounds
        return min(component_risk, 10.0)

    def calculate_asset_risk(self, asset: Asset, data_obj=None) -> Union[float, Tuple]:
        """
        Calculate risk score for an asset
        
        Args:
            asset: Asset object
            data_obj: Optional data object for detailed analysis
            
        Returns:
            Float risk score if no data_obj, otherwise tuple with detailed analysis
        """
        if data_obj is None:
            # Simple asset risk calculation
            if not asset.components:
                return 0.0
            
            # Calculate risk from all components
            component_risks = [self.calculate_component_risk(comp) for comp in asset.components]
            
            # Aggregate component risks
            avg_component_risk = sum(component_risks) / len(component_risks)
            
            # Factor in asset criticality
            criticality_factor = self.normalize_business_criticality(asset.criticality_level)
            
            # Calculate final asset risk
            asset_risk = avg_component_risk * (1.0 + criticality_factor)
            
            # Ensure risk is within bounds
            return min(asset_risk, 10.0)
        else:
            # Detailed analysis with data_obj (original method)
            return self._calculate_asset_risk_detailed(asset, data_obj)

    def _calculate_asset_risk_detailed(self, data: Asset, data_obj) -> Tuple[List[float], List[float], List[float], float]:
        """
        Original detailed asset risk calculation method
        
        Args:
            data: Asset object
            data_obj: PyTorch Geometric Data object
            
        Returns:
            Tuple of (direct risks, propagated risks, total risks, total propagated risk)
        """
        # Get node features and edge index from data object
        node_features = data_obj.x
        edge_index = data_obj.edge_index
        
        # Calculate centrality
        if len(data.components) > 0:
            G = nx.DiGraph()
            for i in range(len(data.components)):
                G.add_node(i)
            
            # Add edges from edge_index
            if edge_index.numel() > 0:
                edges = edge_index.t().tolist()
                for edge in edges:
                    G.add_edge(edge[0], edge[1])
            
            try:
                centrality_tensor, centrality_dict = self.calculate_centrality(G)
            except ValueError:
                # Fallback for empty/disconnected graph
                centrality_dict = {i: 1.0 for i in range(len(data.components))}
                centrality_tensor = torch.ones(len(data.components), 1)
        else:
            centrality_dict = {}
            centrality_tensor = torch.tensor([])
        
        # Calculate vulnerability data for propagation
        vulnerabilities_for_propagation = []
        component_idx = 0
        
        for component in data.components:
            for vulnerability in component.vulnerabilities:
                # Calculate exploit and propagation likelihoods
                exploit_likelihood = self.calculate_exploit_likelihood(vulnerability)
                propagation_likelihood = self.calculate_propagation_likelihood(vulnerability)
                
                vulnerability.exploit_likelihood = exploit_likelihood
                vulnerability.propagation_likelihood = propagation_likelihood
                
                centrality_value = centrality_dict.get(component_idx, 0.0)
                
                # Calculate direct risk
                direct_risk = self.calculate_direct_risk(
                    exploit_likelihood, 
                    vulnerability.impact / 10.0 if vulnerability.impact > 0 else vulnerability.cvss / 10.0,
                    centrality_value
                )
                
                vulnerabilities_for_propagation.append({
                    'node_idx': component_idx,
                    'direct_risk': direct_risk,
                    'propagation_likelihood': propagation_likelihood,
                    'impact': vulnerability.impact / 10.0 if vulnerability.impact > 0 else vulnerability.cvss / 10.0
                })
            
            component_idx += 1
        
        # Calculate propagated risks
        propagated_risks = self.propagate_risk_bfs(data_obj, vulnerabilities_for_propagation)
        
        # Calculate direct risks for each component
        direct_risks = []
        total_risks = []
        
        for i, component in enumerate(data.components):
            component_direct_risk = 0.0
            for vulnerability in component.vulnerabilities:
                exploit_likelihood = getattr(vulnerability, 'exploit_likelihood', 
                                           self.calculate_exploit_likelihood(vulnerability))
                centrality_value = centrality_dict.get(i, 0.0)
                impact = vulnerability.impact / 10.0 if vulnerability.impact > 0 else vulnerability.cvss / 10.0
                
                direct_risk = self.calculate_direct_risk(exploit_likelihood, impact, centrality_value)
                component_direct_risk += direct_risk
            
            direct_risks.append(component_direct_risk)
            
            # Total risk = direct + propagated
            propagated_risk = propagated_risks[i] if i < len(propagated_risks) else 0.0
            total_risk = component_direct_risk + propagated_risk
            total_risks.append(total_risk)
        
        # Calculate total propagated risk for the asset
        total_propagated_risk = sum(total_risks)
        
        return direct_risks, propagated_risks, total_risks, total_propagated_risk
    
    def calculate_centrality(self, G: nx.DiGraph) -> Tuple[torch.Tensor, Dict[int, float]]:
        """
        Calculate centrality metrics for a graph
        
        Args:
            G: NetworkX directed graph
            
        Returns:
            Tuple of (centrality tensor, centrality dictionary)
        """
        if len(G) == 0:
            raise ValueError("Graph is empty. Cannot calculate centrality.")
        
        if not G.is_directed():
            G = G.to_directed()
        
        # Calculate multiple centrality measures
        in_degree_centrality = nx.in_degree_centrality(G)
        out_degree_centrality = nx.out_degree_centrality(G)
        betweenness_centrality = nx.betweenness_centrality(G, normalized=True, endpoints=True)
        pagerank = nx.pagerank(G, alpha=0.85)
        
        # Combine centrality measures
        centrality = {}
        for node in G.nodes():
            centrality[node] = (
                in_degree_centrality[node] +
                out_degree_centrality[node] +
                betweenness_centrality[node] +
                pagerank[node]
            ) / 4
        
        # Normalize centrality values
        max_centrality = max(centrality.values()) if centrality else 1.0
        for node in centrality:
            centrality[node] /= max_centrality
        
        # Convert to tensor
        centrality_tensor = torch.tensor(
            [centrality[node] for node in G.nodes()], 
            dtype=torch.float32
        ).unsqueeze(1)
        
        return centrality_tensor, centrality
    
    def calculate_cvs(self, vulnerabilities: List[Vulnerability]) -> float:
        """
        Calculate Component Vulnerability Score (CVS)
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            CVS score
        """
        sum_severity = {'C': 0, 'H': 0, 'M': 0, 'L': 0}
        count_severity = {'C': 0, 'H': 0, 'M': 0, 'L': 0}
        
        for vuln in vulnerabilities:
            cvss = vuln.cvss
            for scale, (low, high) in self.severity_scales.items():
                if low <= cvss <= high:
                    sum_severity[scale] += cvss
                    count_severity[scale] += 1
                    break
        
        # Calculate weighted sum
        weighted_sum = sum(
            self.cvss_weights[scale] * sum_severity[scale] 
            for scale in self.severity_scales.keys()
        )
        
        # Calculate weighted average
        total_weight = sum(self.cvss_weights.values())
        weighted_average = weighted_sum / total_weight if total_weight > 0 else 0
        
        # Incorporate vulnerability count factor
        total_count = sum(count_severity.values())
        vulnerability_factor = 1 + 0 * total_count  # Currently no count factor
        
        return weighted_average * vulnerability_factor if total_count > 0 else 0
    
    def calculate_exploit_likelihood(self, vulnerability: Vulnerability) -> float:
        """
        Calculate exploit likelihood for a vulnerability
        
        Args:
            vulnerability: Vulnerability object
            
        Returns:
            Exploit likelihood score (0-1)
        """
        # Normalize CVSS likelihood to 0-1 range
        normalized_cvss = vulnerability.likelihood / 10.0
        
        # Ensure EPSS is a float
        epss = float(vulnerability.epss)
        
        # Calculate weighted contributions
        cvss_contribution = self.exploit_weights['cvss'] * normalized_cvss
        epss_contribution = self.exploit_weights['epss'] * epss
        exploit_contribution = self.exploit_weights['exploit'] * float(vulnerability.exploit)
        
        # Sum weighted components
        return cvss_contribution + epss_contribution + exploit_contribution
    
    def calculate_propagation_likelihood(self, vulnerability: Vulnerability) -> float:
        """
        Calculate propagation likelihood for a vulnerability
        
        Args:
            vulnerability: Vulnerability object
            
        Returns:
            Propagation likelihood score (0-1)
        """
        scope_change_contribution = (
            self.propagation_weights['scope_change'] * 
            self._calculate_scope_change(vulnerability)
        )
        ransomware_contribution = (
            self.propagation_weights['ransomware'] * 
            self._calculate_ransomware(vulnerability)
        )
        
        return scope_change_contribution + ransomware_contribution
    
    def calculate_direct_risk(self, exploit_likelihood: float, impact: float, centrality: float) -> float:
        """
        Calculate direct risk for a vulnerability
        
        Args:
            exploit_likelihood: Exploit likelihood score
            impact: Impact score
            centrality: Component centrality score
            
        Returns:
            Direct risk score
        """
        return exploit_likelihood * impact * centrality
    
    def _calculate_scope_change(self, vulnerability: Vulnerability) -> float:
        """Calculate scope change contribution"""
        return 1.0 if vulnerability.scope_changed else 0.0
    
    def _calculate_ransomware(self, vulnerability: Vulnerability) -> float:
        """Calculate ransomware contribution"""
        return float(vulnerability.ransomware)
    
    def normalize_business_criticality(self, criticality_level: int) -> float:
        """
        Normalize business criticality level to 0-1 scale
        
        Args:
            criticality_level: Criticality level (1-6)
            
        Returns:
            Normalized criticality (0-1)
        """
        return self.criticality_mapping.get(criticality_level, 0.1)
    
    def normalize_risks(self, risks: List[float], scale: float = 10.0, epsilon: float = 0.01) -> List[float]:
        """
        Normalize risk scores using Z-score normalization
        
        Args:
            risks: List of risk scores
            scale: Target scale for normalization
            epsilon: Small value to avoid exact 0 or max values
            
        Returns:
            List of normalized risk scores
        """
        if not risks:
            return []
        
        mean_risk = np.mean(risks)
        std_dev_risk = np.std(risks) if np.std(risks) != 0 else 1.0
        
        # Calculate Z-scores
        z_scores = [(risk - mean_risk) / std_dev_risk for risk in risks]
        
        # Min-max normalization on Z-scores
        min_z = min(z_scores)
        max_z = max(z_scores)
        range_z = max_z - min_z if max_z != min_z else 1.0
        
        # Adjust range to ensure values fall within (0, scale)
        adjusted_scale = scale - 2 * epsilon
        
        normalized_risks = [
            ((z - min_z) / range_z) * adjusted_scale + epsilon 
            for z in z_scores
        ]
        
        # Ensure no values are exactly 0 or scale
        normalized_risks = [
            max(min(risk, scale - epsilon), epsilon) 
            for risk in normalized_risks
        ]
        
        return normalized_risks
    
    def propagate_risk_bfs(self, data_obj, vulnerabilities: List[Dict[str, Any]]) -> List[float]:
        """
        Calculate propagated risks using BFS approach
        
        Args:
            data_obj: PyTorch Geometric Data object
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            List of propagated risk scores
        """
        adjacency_matrix = data_obj.adj.numpy()
        components = [
            {
                'risk_cvs': data_obj.x[i, 2].item(), 
                'centrality': data_obj.x[i, 1].item()
            } 
            for i in range(data_obj.x.shape[0])
        ]
        
        def bfs(start_idx: int, propagation_likelihood: float, impact: float) -> float:
            """BFS to calculate indirect risk"""
            indirect_risk = 0.0
            queue = [(start_idx, 0)]
            visited = set()
            
            while queue:
                current_idx, cumulative_weight = queue.pop(0)
                
                if current_idx not in visited:
                    visited.add(current_idx)
                    
                    for neighbor_idx in range(len(components)):
                        if (adjacency_matrix[neighbor_idx, current_idx] > 0 and 
                            neighbor_idx not in visited):
                            edge_weight = adjacency_matrix[neighbor_idx, current_idx]
                            new_cumulative_weight = cumulative_weight + edge_weight
                            indirect_risk += edge_weight * impact
                            queue.append((neighbor_idx, new_cumulative_weight))
            
            indirect_risk *= propagation_likelihood
            return round(indirect_risk, 5)
        
        total_propagated_risks = []
        
        for vulnerability in vulnerabilities:
            component_idx = int(vulnerability['node_idx'])  # Already 0-based indexing
            direct_risk = vulnerability['direct_risk']
            impact = vulnerability['impact']
            propagation_likelihood = vulnerability['propagation_likelihood']
            
            # Calculate indirect risk only if propagation likelihood is high enough
            if propagation_likelihood >= 0.5:
                indirect_risk = bfs(component_idx, propagation_likelihood, impact)
                total_risk = direct_risk + indirect_risk
            else:
                total_risk = direct_risk
            
            # Ensure total_risk is a regular Python float
            total_propagated_risks.append(float(total_risk))
        
        return total_propagated_risks
    
    def calculate_system_risk(self, G: nx.DiGraph, data: System, 
                            component_centrality: Dict[str, float], 
                            criticality_threshold: int = 6) -> float:
        """
        Calculate system-level risk using a simple, logical approach
        
        Args:
            G: Network communication graph (optional)
            data: System object
            component_centrality: Component centrality data (optional)
            criticality_threshold: Threshold for critical assets
            
        Returns:
            System-level risk score
        """
        if not data.assets:
            return 0.0
        
        # Method 1: Try sophisticated network-based calculation if we have good data
        has_network_graph = G is not None and len(G.edges()) > 0
        max_centrality = max(component_centrality.values()) if component_centrality else 0.0
        has_meaningful_centrality = max_centrality > 0.01
        
        if has_network_graph and has_meaningful_centrality:
            try:
                # Use a reasonable criticality threshold
                effective_threshold = min(criticality_threshold, 3)  # Don't set threshold too high
                critical_assets = [
                    asset for asset in data.assets 
                    if asset.final_criticality >= effective_threshold
                ]
                
                # If no critical assets, take top half
                if not critical_assets:
                    sorted_assets = sorted(data.assets, key=lambda a: a.final_criticality, reverse=True)
                    num_critical = max(1, len(sorted_assets) // 2)
                    critical_assets = sorted_assets[:num_critical]
                
                # Calculate network-based risk
                network_risk = 0.0
                if critical_assets:
                    shortest_paths = self._calculate_shortest_paths(G, critical_assets)
                    for path in shortest_paths.values():
                        path_risk = self._calculate_network_risk(path, data, component_centrality)
                        network_risk += path_risk
                
                # Calculate host-based risk (simple sum with light criticality weighting)
                host_risk = 0.0
                for asset in data.assets:
                    # Light criticality weighting: 0.8-1.2 range instead of extreme scaling
                    criticality_factor = 0.8 + (asset.criticality_level - 1) * 0.1  # 0.8-1.2 range
                    weighted_risk = asset.total_propagated_risk * criticality_factor
                    host_risk += weighted_risk
                
                # Simple combination with light network effect
                system_risk = host_risk + (network_risk * 0.3)  # Light network contribution
                
                # Apply modest system effect (10-30% increase, not 300%!)
                system_multiplier = 1.0 + (len(data.assets) - 1) * 0.05  # 5% per additional asset
                final_risk = system_risk * min(system_multiplier, 1.3)  # Cap at 30% increase
                
                return final_risk
                
            except Exception as e:
                print(f"Network-based calculation failed: {e}")
        
        # Method 2: Simple weighted sum approach (much more reasonable)
        total_weighted_risk = 0.0
        total_weight = 0.0
        
        for asset in data.assets:
            # Simple criticality weighting (0.6-1.0 range)
            criticality_weight = 0.6 + (asset.criticality_level - 1) * 0.1  # 0.6-1.0 range
            
            # Weight the asset risk by criticality
            weighted_risk = asset.total_propagated_risk * criticality_weight
            
            total_weighted_risk += weighted_risk
            total_weight += criticality_weight
        
        # Normalize by weight to get average, then scale by system size
        if total_weight > 0:
            avg_weighted_risk = total_weighted_risk / total_weight
            # Modest system complexity factor: 1.1-1.5x based on system size
            system_complexity = 1.0 + (len(data.assets) - 1) * 0.07  # 7% per additional asset
            system_risk = avg_weighted_risk * len(data.assets) * min(system_complexity, 1.5)
            return system_risk
        
        # Method 3: Fallback to simple sum with slight increase for system effects
        simple_sum = sum(asset.total_propagated_risk for asset in data.assets)
        return simple_sum * 1.2  # Just 20% increase for system interactions
    
    def _calculate_shortest_paths(self, main_graph: nx.DiGraph, 
                                critical_assets: List[Asset]) -> Dict[Tuple[str, str], List[str]]:
        """Calculate shortest paths to critical assets"""
        critical_ips = [asset.ip_address for asset in critical_assets]
        shortest_paths = {}
        visited_edges = set()
        internet_ip = "0.0.0.0"
        
        for dst_ip in critical_ips:
            try:
                path = nx.shortest_path(
                    main_graph, 
                    source=internet_ip, 
                    target=dst_ip, 
                    weight='weight'
                )
                
                # Merge paths and track visited edges
                merged_path = []
                for i in range(len(path) - 1):
                    src_ip = path[i]
                    dst_ip_path = path[i + 1]
                    edge = (src_ip, dst_ip_path)
                    
                    if edge not in visited_edges:
                        merged_path.append(src_ip)
                        visited_edges.add(edge)
                
                # Add final destination
                if merged_path and merged_path[-1] != dst_ip:
                    merged_path.append(dst_ip)
                
                if merged_path:
                    shortest_paths[(internet_ip, dst_ip)] = merged_path
                    
            except nx.NetworkXNoPath:
                continue
        
        return shortest_paths
    
    def _calculate_network_risk(self, path: List[str], data: System, 
                              component_centrality: Dict[str, float]) -> float:
        """Calculate network risk for a specific path"""
        path_risk = 0.0
        
        for i in range(len(path) - 1):
            current_ip = path[i]
            next_ip = path[i + 1]
            
            # Find assets involved in this path segment
            current_asset = next((a for a in data.assets if a.ip_address == current_ip), None)
            next_asset = next((a for a in data.assets if a.ip_address == next_ip), None)
            
            if current_asset and next_asset:
                # Calculate risk based on asset criticality and centrality
                current_criticality = float(current_asset.updated_criticality)
                next_criticality = float(next_asset.updated_criticality)
                
                # Use component centrality if available
                current_centrality = max(
                    component_centrality.get(f"A{current_asset.asset_id}_{comp.name}", 0)
                    for comp in current_asset.components
                ) if current_asset.components else 0
                
                next_centrality = max(
                    component_centrality.get(f"A{next_asset.asset_id}_{comp.name}", 0)
                    for comp in next_asset.components
                ) if next_asset.components else 0
                
                # Calculate segment risk
                segment_risk = (
                    current_criticality * current_centrality +
                    next_criticality * next_centrality
                ) / 2
                
                path_risk += segment_risk
        
        return path_risk
    
    def recalculate_asset_criticality(self, assets: List[Asset], 
                                    centrality_data: Dict[str, float]) -> Tuple[Dict[str, float], Dict[str, int]]:
        """
        Recalculate asset criticality based on centrality
        
        Args:
            assets: List of assets
            centrality_data: Asset centrality data
            
        Returns:
            Tuple of (updated criticality, final criticality)
        """
        final_criticality = {}
        updated_criticality = {}
        
        # Check if centrality data is meaningful (not all zeros)
        max_centrality = max(centrality_data.values()) if centrality_data else 0.0
        has_meaningful_centrality = max_centrality > 0.01  # Threshold for meaningful centrality
        
        for asset in assets:
            asset_id = str(asset.asset_id)  # Ensure string key
            business_criticality = asset.criticality_level
            normalized_centrality = centrality_data.get(asset_id, 0.0)
            
            # Normalize business criticality
            normalized_business_criticality = self.normalize_business_criticality(business_criticality)
            
            if has_meaningful_centrality:
                # Use centrality-based calculation
                combined_criticality = (
                    0.4 * normalized_business_criticality + 
                    0.6 * normalized_centrality
                )
            else:
                # Fallback to business criticality when centrality data is poor
                combined_criticality = normalized_business_criticality
                print(f"Warning: Using business criticality fallback for asset {asset_id} (centrality: {normalized_centrality})")
            
            updated_criticality[asset_id] = combined_criticality
            
            # Convert to meaningful final criticality scale (1-10 range)
            # Scale from 0-1 range to 1-10 range for better thresholding
            integer_final_criticality = int(max(1, min(10, int(combined_criticality * 9) + 1)))
            final_criticality[asset_id] = integer_final_criticality
        
        return updated_criticality, final_criticality


# Convenience functions for backward compatibility
def calculate_centrality(G: nx.DiGraph) -> Tuple[torch.Tensor, Dict[int, float]]:
    """Backward compatibility function"""
    calculator = RiskCalculator()
    return calculator.calculate_centrality(G)


def calculate_cvs(vulnerabilities: List[Vulnerability]) -> float:
    """Backward compatibility function"""
    calculator = RiskCalculator()
    return calculator.calculate_cvs(vulnerabilities)


def calculate_exploit_likelihood(vulnerability: Vulnerability) -> float:
    """Backward compatibility function"""
    calculator = RiskCalculator()
    return calculator.calculate_exploit_likelihood(vulnerability)


def calculate_propagation_likelihood(vulnerability: Vulnerability) -> float:
    """Backward compatibility function"""
    calculator = RiskCalculator()
    return calculator.calculate_propagation_likelihood(vulnerability)


def calculate_direct_risk(exploit_likelihood: float, impact: float, centrality: float) -> float:
    """Backward compatibility function"""
    calculator = RiskCalculator()
    return calculator.calculate_direct_risk(exploit_likelihood, impact, centrality)


def normalize_business_criticality_rule_based(criticality_level: int) -> float:
    """Backward compatibility function"""
    calculator = RiskCalculator()
    return calculator.normalize_business_criticality(criticality_level)


def recalculate_asset_criticality(assets: List[Asset], centrality_data: Dict[str, float]) -> Tuple[Dict[str, float], Dict[str, int]]:
    """Backward compatibility function"""
    calculator = RiskCalculator()
    return calculator.recalculate_asset_criticality(assets, centrality_data) 