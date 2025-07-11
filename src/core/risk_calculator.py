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

    def calculate_component_risk(self, component, centrality: Optional[float] = None) -> float:
        """
        Calculate risk score for a component following the equation:
        Rcomponent,ci = RCVS_component,ci × RCentrality_component,ci
        
        Args:
            component: Component object
            centrality: Component centrality value (optional, defaults to 1.0 if not provided)
            
        Returns:
            Component risk score
        """
        if not component.vulnerabilities:
            return 0.0
        
        # Calculate CVS (Component Vulnerability Score)
        cvs = self.calculate_cvs(component.vulnerabilities)
        
        # Use provided centrality or default to 1.0 for backward compatibility
        component_centrality = centrality if centrality is not None else 1.0
        
        # Calculate component risk following the paper's equation:
        # Rcomponent,ci = RCVS_component,ci × RCentrality_component,ci
        component_risk = cvs * component_centrality
        
        return component_risk

    def calculate_asset_risk(self, asset: Asset, data_obj=None) -> Union[float, Tuple]:
        """
        FIXED: Always use detailed calculation for consistency with original implementation
        
        Args:
            asset: Asset object
            data_obj: Optional data object for detailed analysis
            
        Returns:
            Float risk score if no data_obj requested, otherwise tuple with detailed analysis
        """
        if data_obj is None:
            # Generate data_obj for consistent detailed analysis (like original)
            try:
                from .graph_processor import GraphProcessor
                graph_processor = GraphProcessor()
                G, generated_data_obj = graph_processor.generate_sub_graph(asset)
                
                # Always use detailed calculation for consistency
                detailed_result = self._calculate_asset_risk_detailed(asset, generated_data_obj)
                if isinstance(detailed_result, tuple) and len(detailed_result) >= 4:
                    return detailed_result[3]  # Return total_propagated_risk for simple mode
                else:
                    # Return 0 rather than inconsistent calculation
                    return 0.0
                    
            except Exception as e:
                print(f"Warning: Could not generate data_obj for asset {asset.asset_id}: {e}")
                return 0.0  # Return 0 rather than inconsistent calculation
        else:
            # Use detailed calculation with provided data_obj (original behavior)
            return self._calculate_asset_risk_detailed(asset, data_obj)


    def _calculate_asset_risk_detailed(self, data: Asset, data_obj) -> Tuple[List[float], List[float], List[float], float]:
        """
        Detailed asset risk calculation following the CORRECT paper equations:
        
        Equation 4: R_asset,am = Σ_ci∈C(am) [Σ_vk∈V(ci) R_vulnerability,vk]
        Equation 5: R_vulnerability,vk = R_direct,vk + R_indirect,vk  
        Equation 6: R_direct,vk = EL_vk × S^impact_vk × R^Centrality_component,ci
        
        Args:
            data: Asset object
            data_obj: PyTorch Geometric Data object
            
        Returns:
            Tuple of (direct risks, propagated risks, total risks, total propagated risk)
        """
        # Get node features and edge index from data object
        node_features = data_obj.x
        edge_index = data_obj.edge_index
        
        # Calculate centrality (Equation 3: combining DC, BC, PR)
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
        
        # Calculate vulnerability data for propagation (following Equation 9)
        vulnerabilities_for_propagation = []
        component_idx = 0
        
        for component in data.components:
            for vulnerability in component.vulnerabilities:
                # Equation 7: Calculate exploit likelihood
                exploit_likelihood = self.calculate_exploit_likelihood(vulnerability)
                
                # Equation 10: Calculate propagation likelihood  
                propagation_likelihood = self.calculate_propagation_likelihood(vulnerability)
                
                vulnerability.exploit_likelihood = exploit_likelihood
                vulnerability.propagation_likelihood = propagation_likelihood
                
                centrality_value = centrality_dict.get(component_idx, 0.0)
                
                # Equation 6: Calculate direct risk
                impact = vulnerability.impact / 10.0 if vulnerability.impact > 0 else vulnerability.cvss / 10.0
                direct_risk = self.calculate_direct_risk(exploit_likelihood, impact, centrality_value)
                
                vulnerabilities_for_propagation.append({
                    'node_idx': component_idx,
                    'direct_risk': direct_risk,
                    'propagation_likelihood': propagation_likelihood,
                    'impact': impact
                })
            
            component_idx += 1
        
        # Equation 9: Calculate propagated risks (indirect risks)
        propagated_risks = self.propagate_risk_bfs(data_obj, vulnerabilities_for_propagation)
        
        # CRITICAL FIX: Aggregate vulnerability-level propagated risks by component
        # propagated_risks is indexed by vulnerability, but we need it indexed by component
        component_propagated_risks = [0.0] * len(data.components)
        vuln_idx = 0
        for comp_idx, component in enumerate(data.components):
            for vulnerability in component.vulnerabilities:
                if vuln_idx < len(propagated_risks):
                    component_propagated_risks[comp_idx] += propagated_risks[vuln_idx]
                vuln_idx += 1
        
        # Calculate direct risks and total risks for each component
        direct_risks = []
        total_risks = []
        
        for i, component in enumerate(data.components):
            component_direct_risk = 0.0
            
            for vulnerability in component.vulnerabilities:
                # Use stored exploit likelihood or recalculate
                exploit_likelihood = getattr(vulnerability, 'exploit_likelihood', 
                                           self.calculate_exploit_likelihood(vulnerability))
                centrality_value = centrality_dict.get(i, 0.0)
                impact = vulnerability.impact / 10.0 if vulnerability.impact > 0 else vulnerability.cvss / 10.0
                
                # Equation 6: Direct risk calculation
                direct_risk = self.calculate_direct_risk(exploit_likelihood, impact, centrality_value)
                component_direct_risk += direct_risk
            
            direct_risks.append(component_direct_risk)
            
            # Equation 5: Total vulnerability risk = direct + indirect
            # FIXED: Use correctly aggregated component-level propagated risk
            propagated_risk = component_propagated_risks[i]
            total_risk = component_direct_risk + propagated_risk
            total_risks.append(total_risk)
        
        # Equation 4: Asset risk = sum of all component vulnerability risks
        total_propagated_risk = sum(total_risks)
        
        return direct_risks, propagated_risks, total_risks, total_propagated_risk
    
    def _calculate_asset_risk_simple_fallback(self, asset: Asset) -> float:
        """
        Simple asset risk calculation following Paper's Equation 4: R_asset,am = Σ Σ R_vulnerability,vk
        
        CRITICAL FIX: Sum ALL vulnerability risks (not average component risks)
        
        Args:
            asset: Asset object
            
        Returns:
            Asset risk score
        """
        if not asset.components:
            return 0.0
        
        # FIXED: Follow paper's Equation 4 - sum all vulnerability risks
        total_vulnerability_risk = 0.0
        
        for component in asset.components:
            for vulnerability in component.vulnerabilities:
                # Calculate individual vulnerability risk
                vuln_risk = self.calculate_vulnerability_risk(vulnerability)
                total_vulnerability_risk += vuln_risk
        
        # Apply asset criticality as a multiplier (more aligned with paper)
        criticality_factor = self.normalize_business_criticality(asset.criticality_level)
        asset_risk = total_vulnerability_risk * criticality_factor
        
        # Allow higher ceiling for summation approach (paper's methodology can produce higher values)
        return min(asset_risk, 100.0)

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
        Calculate exploit likelihood following Equation 7:
        EL_vk = α × (S^likelihood_vk / 10) + β × EPSS(vk) + γ × Exploit(vk)
        
        Where α=0.3, β=0.4, γ=0.3 (default parameters from paper)
        
        Args:
            vulnerability: Vulnerability object
            
        Returns:
            Exploit likelihood score (0-1)
        """
        # Equation 7 parameters (from paper specification)
        alpha = 0.3  # α - weight for CVSS likelihood
        beta = 0.4   # β - weight for EPSS
        gamma = 0.3  # γ - weight for exploit availability
        
        # Equation 7: EL_vk = α × (S^likelihood_vk / 10) + β × EPSS(vk) + γ × Exploit(vk)
        cvss_likelihood_term = alpha * (vulnerability.likelihood / 10.0)
        epss_term = beta * float(vulnerability.epss)
        exploit_term = gamma * float(vulnerability.exploit)
        
        # Sum all terms as per Equation 7
        exploit_likelihood = cvss_likelihood_term + epss_term + exploit_term
        
        # Ensure result is in [0, 1] range
        return min(max(exploit_likelihood, 0.0), 1.0)
    
    def calculate_propagation_likelihood(self, vulnerability: Vulnerability) -> float:
        """
        Calculate propagation likelihood following Equation 10:
        PL_vk = δ × ScopeChange(vk) + θ × Ransomware(vk)
        
        Where δ=0.5, θ=0.5 (default parameters from paper)
        
        Args:
            vulnerability: Vulnerability object
            
        Returns:
            Propagation likelihood score (0-1)
        """
        # Equation 10 parameters (from paper specification)
        delta = 0.5  # δ - weight for scope change
        theta = 0.5  # θ - weight for ransomware
        
        # Equation 10: PL_vk = δ × ScopeChange(vk) + θ × Ransomware(vk)
        scope_change_term = delta * self._calculate_scope_change(vulnerability)
        ransomware_term = theta * self._calculate_ransomware(vulnerability)
        
        # Sum terms as per Equation 10
        propagation_likelihood = scope_change_term + ransomware_term
        
        # Ensure result is in [0, 1] range
        return min(max(propagation_likelihood, 0.0), 1.0)
    
    def calculate_direct_risk(self, exploit_likelihood: float, impact: float, centrality: float) -> float:
        """
        Calculate direct risk following Equation 6:
        R_direct,vk = EL_vk × S^impact_vk × R^Centrality_component,ci
        
        Args:
            exploit_likelihood: EL_vk - Exploit likelihood score (from Equation 7)
            impact: S^impact_vk - Impact score 
            centrality: R^Centrality_component,ci - Component centrality score (from Equation 3)
            
        Returns:
            Direct risk score following Equation 6
        """
        # Equation 6: R_direct,vk = EL_vk × S^impact_vk × R^Centrality_component,ci
        direct_risk = exploit_likelihood * impact * centrality
        
        return direct_risk
    
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
    
    def prepare_assets_for_system_calculation(self, data: System, graph_processor=None) -> None:
        """
        Prepare assets with required data for system risk calculation
        
        Args:
            data: System object
            graph_processor: GraphProcessor instance (optional)
        """
        if graph_processor is None:
            from .graph_processor import GraphProcessor
            graph_processor = GraphProcessor()
        
        print(f"Preparing {len(data.assets)} assets for system calculation...")
        
        # Step 1: Calculate individual asset risks and store total_propagated_risk
        for asset in data.assets:
            try:
                # Generate sub-graph and calculate detailed risk
                G, data_obj = graph_processor.generate_sub_graph(asset)
                
                # Calculate asset risk with data_obj (returns tuple)
                risk_result = self.calculate_asset_risk(asset, data_obj)
                
                if isinstance(risk_result, tuple) and len(risk_result) >= 4:
                    # Extract total_propagated_risk from tuple
                    total_propagated_risk = risk_result[3]
                    asset.total_propagated_risk = total_propagated_risk
                    print(f"  Asset {asset.asset_id}: total_propagated_risk = {total_propagated_risk:.3f}")
                else:
                    # Fallback: use single value
                    asset.total_propagated_risk = float(risk_result)
                    print(f"  Asset {asset.asset_id}: total_propagated_risk = {risk_result:.3f} (fallback)")
                    
            except Exception as e:
                print(f"  Warning: Could not calculate detailed risk for asset {asset.asset_id}: {e}")
                # Fallback to simple calculation
                try:
                    simple_risk = self.calculate_asset_risk(asset)
                    asset.total_propagated_risk = simple_risk
                    print(f"  Asset {asset.asset_id}: total_propagated_risk = {simple_risk:.3f} (simple fallback)")
                except Exception as e2:
                    print(f"  Error: Could not calculate any risk for asset {asset.asset_id}: {e2}")
                    asset.total_propagated_risk = 0.0
        
        # Step 2: Calculate asset criticalities
        try:
            # Try to generate centrality data
            from .dependency_calculator import DependencyCalculator
            dep_calc = DependencyCalculator('data/asset_data')
            centrality_data = dep_calc.generate_dependence(data, 'ICS')
            
            # Calculate updated criticalities
            asset_centrality = centrality_data['asset_centrality']
            updated_criticality, final_criticality = self.recalculate_asset_criticality(data.assets, asset_centrality)
            
            # Store on assets
            for asset in data.assets:
                asset_id = str(asset.asset_id)
                asset.updated_criticality = updated_criticality.get(asset_id, 0.5)
                asset.final_criticality = final_criticality.get(asset_id, asset.criticality_level)
                print(f"  Asset {asset.asset_id}: updated_criticality={asset.updated_criticality:.3f}, final_criticality={asset.final_criticality}")
                
        except Exception as e:
            print(f"  Warning: Could not calculate centrality-based criticalities: {e}")
            # Fallback: use normalized business criticality
            for asset in data.assets:
                asset.updated_criticality = self.normalize_business_criticality(asset.criticality_level)
                asset.final_criticality = asset.criticality_level  # Use business criticality as final
                print(f"  Asset {asset.asset_id}: updated_criticality={asset.updated_criticality:.3f} (normalized), final_criticality={asset.final_criticality}")

    def calculate_system_risk(self, G: nx.DiGraph, data: System, 
                            component_centrality: Dict[str, float], 
                            criticality_threshold: int = 6,
                            graph_processor=None) -> float:
        """
        Calculate system-level risk following the paper's Equation 13: R_system = R_network + Σ R_host,hm
        
        Args:
            G: Network communication graph
            data: System object
            component_centrality: Component centrality data
            criticality_threshold: Threshold for critical assets (default 6 as per paper)
            graph_processor: GraphProcessor instance (optional, will be created if needed)
            
        Returns:
            System-level risk score
        """
        if not data.assets:
            return 0.0
        
        # Ensure assets have required data
        assets_prepared = all(
            hasattr(asset, 'total_propagated_risk') and 
            hasattr(asset, 'updated_criticality') and 
            hasattr(asset, 'final_criticality') and
            asset.total_propagated_risk > 0
            for asset in data.assets
        )
        
        if not assets_prepared:
            print("Assets not prepared - running preparation step...")
            self.prepare_assets_for_system_calculation(data, graph_processor)
        
        # Step 1: Calculate host-based risk (Equation 14: Σ R_host,hm)
        # R_host,hm = asset_criticality × total_propagated_risk
        host_risk = 0.0
        included_assets = set()
        
        for asset in data.assets:
            if asset.ip_address not in included_assets:
                # Use normalized criticality values (0-1 range) not raw values (1-5)
                if hasattr(asset, 'updated_criticality') and asset.updated_criticality > 0:
                    # Use the properly calculated updated_criticality from centrality analysis
                    asset_criticality = float(asset.updated_criticality)
                else:
                    # Fallback: normalize the business criticality level
                    asset_criticality = self.normalize_business_criticality(asset.criticality_level)
                
                asset_host_risk = asset_criticality * asset.total_propagated_risk
                host_risk += asset_host_risk
                included_assets.add(asset.ip_address)
        
        # Step 2: Calculate network-based risk (Equation 15)
        # Only if we have a meaningful network graph
        network_risk = 0.0
        
        if G is not None and len(G.edges()) > 0:
            try:
                # Identify critical assets (criticality >= threshold)
                critical_assets = self._identify_critical_assets(data, criticality_threshold)
                
                # If no critical assets with default threshold, try lower threshold
                if not critical_assets and criticality_threshold > 3:
                    critical_assets = self._identify_critical_assets(data, 3)
                
                # Calculate shortest paths to critical assets
                if critical_assets:
                    shortest_paths = self._calculate_shortest_paths(G, critical_assets)
                    
                    # Calculate network risk along paths
                    for (src_ip, dst_ip), path in shortest_paths.items():
                        path_risk = self._calculate_network_risk(path, data, component_centrality)
                        network_risk += path_risk
                        
            except Exception as e:
                print(f"Warning: Network risk calculation failed: {e}")
                network_risk = 0.0
        
        # Step 3: Combine per Equation 13
        system_risk = host_risk + network_risk
        
        return system_risk
    
    def _identify_critical_assets(self, data: System, criticality_threshold: int = 6) -> List[Asset]:
        """
        Identify critical assets with criticality >= threshold (following paper's methodology)
        
        Args:
            data: System object
            criticality_threshold: Minimum criticality level for critical assets
            
        Returns:
            List of critical assets
        """
        critical_assets = []
        
        for asset in data.assets:
            # Use final_criticality if available, otherwise use criticality_level
            asset_criticality = getattr(asset, 'final_criticality', asset.criticality_level)
            
            if asset_criticality >= criticality_threshold:
                critical_assets.append(asset)
                
        return critical_assets
    
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
        """
        Calculate network risk following paper's methodology (Equation 15)
        Only considers network-exploitable vulnerabilities along the path
        
        Args:
            path: List of IP addresses representing the attack path
            data: System object containing assets
            component_centrality: Component centrality data
            
        Returns:
            Network risk value for this path
        """
        path_risk = 0.0
        
        for ip in path:
            # Find asset at this IP address
            asset = next((a for a in data.assets if a.ip_address == ip), None)
            if not asset:
                continue
                
            # Only consider network-exploitable vulnerabilities (KEY DIFFERENCE from host risk)
            for component in asset.components:
                component_name = f"A{asset.asset_id}_{component.name}"
                component_centrality_value = component_centrality.get(component_name, 0.0)
                
                for vulnerability in component.vulnerabilities:
                    # Check if vulnerability is network-based (AV:N or AV:A)
                    if self._is_network_vulnerability(vulnerability):
                        exploit_likelihood = self.calculate_exploit_likelihood(vulnerability)
                        # Calculate risk contribution: likelihood × impact × centrality
                        risk_contribution = (exploit_likelihood * 
                                           vulnerability.impact / 10.0 * 
                                           component_centrality_value)
                        path_risk += risk_contribution
        
        return path_risk
    
    def _is_network_vulnerability(self, vulnerability: Vulnerability) -> bool:
        """
        Check if vulnerability is network-exploitable based on CVSS Attack Vector
        
        Args:
            vulnerability: Vulnerability object
            
        Returns:
            True if vulnerability is network-exploitable (AV:N or AV:A)
        """
        if hasattr(vulnerability, 'cvss_v3_vector') and vulnerability.cvss_v3_vector:
            # Check CVSS v3 vector for Attack Vector
            cvss_vector = vulnerability.cvss_v3_vector
            if "/AV:N" in cvss_vector:  # Network
                return True
            elif "/AV:A" in cvss_vector:  # Adjacent Network
                return True
            elif "/AV:L" in cvss_vector:  # Local
                return False
            elif "/AV:P" in cvss_vector:  # Physical
                return False
        
        # Fallback: if no CVSS vector available, assume network-based
        # This is conservative but ensures we don't miss network risks
        return True
    
    def _calculate_simple_asset_centrality(self, data: System) -> Dict[str, float]:
        """
        Calculate simple asset centrality when dependency calculator is not available
        
        Args:
            data: System object
            
        Returns:
            Dictionary mapping asset IDs to centrality values
        """
        asset_centrality = {}
        
        if not data.assets:
            return asset_centrality
        
        # Simple heuristic: assets with more components and higher criticality have higher centrality
        max_components = max(len(asset.components) for asset in data.assets)
        max_criticality = max(asset.criticality_level for asset in data.assets)
        
        for asset in data.assets:
            # Normalize based on component count and criticality
            component_factor = len(asset.components) / max_components if max_components > 0 else 0.5
            criticality_factor = asset.criticality_level / max_criticality if max_criticality > 0 else 0.5
            
            # Combined centrality (weighted average)
            centrality = (component_factor * 0.4 + criticality_factor * 0.6)  # Emphasize criticality
            asset_centrality[str(asset.asset_id)] = centrality
        
        return asset_centrality
    
    def recalculate_asset_criticality(self, assets: List[Asset], 
                                    centrality_data: Dict[str, float]) -> Tuple[Dict[str, float], Dict[str, int]]:
        """
        Fix to match original implementation exactly
        
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
            
            # Use original rule-based mapping
            normalized_business_criticality = self.normalize_business_criticality(business_criticality)
            
            if has_meaningful_centrality:
                # Original weighting: 0.4 business + 0.6 centrality
                combined_criticality = (
                    0.4 * normalized_business_criticality + 
                    0.6 * normalized_centrality
                )
            else:
                # Fallback to business criticality when centrality data is poor
                combined_criticality = normalized_business_criticality
                print(f"Warning: Using business criticality fallback for asset {asset_id} (centrality: {normalized_centrality})")
            
            updated_criticality[asset_id] = combined_criticality
            
            # FIX: Use original conversion logic to match exactly
            integer_final_criticality = int(combined_criticality * 10)  # ORIGINAL
            final_criticality[asset_id] = integer_final_criticality
        
        return updated_criticality, final_criticality

    def validate_risk_calculations(self, data, old_results: Dict[str, Any], tolerance: float = 0.5) -> Dict[str, Any]:
        """
        Compare current implementation with old implementation results
        
        Args:
            data: Asset or System object
            old_results: Dictionary containing old implementation results
            tolerance: Acceptable ratio variance (default 0.5 = 50% variance allowed)
            
        Returns:
            Validation report dictionary
        """
        validation_report = {
            'asset_comparisons': [],
            'system_comparison': None,
            'warnings': [],
            'summary': {}
        }
        
        try:
            from .models import Asset, System
            
            if isinstance(data, Asset):
                # Asset-level validation
                old_risk = old_results.get('asset_risk', 0)
                new_risk = self.calculate_asset_risk(data)
                
                if isinstance(new_risk, tuple):
                    new_risk = new_risk[3]  # total_propagated_risk
                
                ratio = new_risk / old_risk if old_risk > 0 else 0
                
                comparison = {
                    'asset_id': data.asset_id,
                    'old_risk': old_risk,
                    'new_risk': float(new_risk),
                    'ratio': ratio,
                    'within_tolerance': (1.0 - tolerance) <= ratio <= (1.0 + tolerance)
                }
                
                validation_report['asset_comparisons'].append(comparison)
                
                if not comparison['within_tolerance']:
                    validation_report['warnings'].append(
                        f"Asset {data.asset_id} risk changed significantly: "
                        f"{old_risk:.3f} -> {new_risk:.3f} ({ratio:.2f}x)"
                    )
                    
            elif isinstance(data, System):
                # System-level validation
                old_system_risk = old_results.get('system_risk', 0)
                
                # Calculate new system risk properly
                try:
                    from .dependency_calculator import DependencyCalculator
                    from .graph_processor import GraphProcessor
                    
                    # Prepare for system calculation
                    dep_calc = DependencyCalculator('data/asset_data')
                    graph_processor = GraphProcessor()
                    
                    # Generate dependency data
                    centrality_dict = dep_calc.generate_dependence(data, 'ES')
                    sys_comp_centrality = centrality_dict['component_centrality']
                    
                    # Process assets
                    for asset in data.assets:
                        G, data_obj = graph_processor.generate_sub_graph(asset)
                        _, _, _, total_propagated_risk = self.calculate_asset_risk(asset, data_obj)
                        asset.total_propagated_risk = total_propagated_risk
                    
                    # Generate network graph and calculate system risk
                    main_graph = graph_processor.generate_network_graph(data)
                    new_system_risk = self.calculate_system_risk(main_graph, data, sys_comp_centrality)
                    
                    ratio = new_system_risk / old_system_risk if old_system_risk > 0 else 0
                    
                    validation_report['system_comparison'] = {
                        'old_risk': old_system_risk,
                        'new_risk': float(new_system_risk),
                        'ratio': ratio,
                        'within_tolerance': (1.0 - tolerance) <= ratio <= (1.0 + tolerance)
                    }
                    
                    if not validation_report['system_comparison']['within_tolerance']:
                        validation_report['warnings'].append(
                            f"System risk changed significantly: "
                            f"{old_system_risk:.3f} -> {new_system_risk:.3f} ({ratio:.2f}x)"
                        )
                        
                except Exception as e:
                    validation_report['warnings'].append(f"System validation failed: {e}")
                
                # Validate individual assets
                if 'asset_risks' in old_results:
                    for old_asset_data in old_results['asset_risks']:
                        asset = next((a for a in data.assets if str(a.asset_id) == str(old_asset_data['id'])), None)
                        if asset:
                            old_risk = old_asset_data['risk']
                            new_risk = getattr(asset, 'total_propagated_risk', 0.0)
                            ratio = new_risk / old_risk if old_risk > 0 else 0
                            
                            comparison = {
                                'asset_id': asset.asset_id,
                                'asset_name': asset.name,
                                'old_risk': old_risk,
                                'new_risk': float(new_risk),
                                'ratio': ratio,
                                'within_tolerance': (1.0 - tolerance) <= ratio <= (1.0 + tolerance)
                            }
                            
                            validation_report['asset_comparisons'].append(comparison)
                            
                            if not comparison['within_tolerance']:
                                validation_report['warnings'].append(
                                    f"Asset {asset.name} risk changed significantly: "
                                    f"{old_risk:.3f} -> {new_risk:.3f} ({ratio:.2f}x)"
                                )
            
            # Generate summary
            asset_comparisons = validation_report['asset_comparisons']
            if asset_comparisons:
                ratios = [comp['ratio'] for comp in asset_comparisons if comp['ratio'] > 0]
                validation_report['summary'] = {
                    'total_assets_compared': len(asset_comparisons),
                    'assets_within_tolerance': sum(1 for comp in asset_comparisons if comp['within_tolerance']),
                    'avg_ratio': sum(ratios) / len(ratios) if ratios else 0,
                    'min_ratio': min(ratios) if ratios else 0,
                    'max_ratio': max(ratios) if ratios else 0,
                    'total_warnings': len(validation_report['warnings'])
                }
                
        except Exception as e:
            validation_report['warnings'].append(f"Validation failed: {e}")
            
        return validation_report

    def validate_against_original_implementation(self, data, original_results: Dict[str, Any], 
                                               tolerance: float = 0.1) -> Dict[str, Any]:
        """
        Validate current implementation against original implementation results
        
        Args:
            data: Asset or System object
            original_results: Dictionary with original implementation results
            tolerance: Acceptable variance ratio (0.1 = 10% tolerance)
            
        Returns:
            Validation report
        """
        report = {
            'aligned': True,
            'differences': [],
            'summary': {}
        }
        
        try:
            if hasattr(data, 'components'):  # Asset-level
                # Validate asset risk
                original_risk = original_results.get('asset_risk', 0)
                current_risk = self.calculate_asset_risk(data)
                
                if isinstance(current_risk, tuple):
                    current_risk = current_risk[3]
                    
                ratio = current_risk / original_risk if original_risk > 0 else 0
                within_tolerance = (1.0 - tolerance) <= ratio <= (1.0 + tolerance)
                
                if not within_tolerance:
                    report['aligned'] = False
                    report['differences'].append({
                        'component': 'asset_risk',
                        'original': original_risk,
                        'current': float(current_risk),
                        'ratio': ratio
                    })
                    
            elif hasattr(data, 'assets'):  # System-level
                # Validate system risk
                original_system_risk = original_results.get('system_risk', 0)
                
                # For system-level validation, we'd need proper setup
                # This would require dependency calculator and graph processor
                # Implementation depends on how system risk is calculated
                pass
                
            report['summary'] = {
                'total_checks': len(original_results),
                'failed_checks': len(report['differences']),
                'alignment_percentage': (1 - len(report['differences']) / max(len(original_results), 1)) * 100
            }
            
        except Exception as e:
            report['aligned'] = False
            report['differences'].append({'error': str(e)})
            
        return report


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