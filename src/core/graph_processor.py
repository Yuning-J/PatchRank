"""
Unified graph processing module for PatchRank
Handles graph generation, centrality calculations, and data preparation for both asset and system levels
"""

import torch
import numpy as np
import networkx as nx
from torch_geometric.data import Data
from torch_geometric.utils import to_dense_adj
from typing import Tuple, Dict, Any, List, Optional

from .models import Asset, System, Component, Vulnerability
from .risk_calculator import RiskCalculator


class GraphProcessor:
    """Unified graph processor for both asset and system level analysis"""
    
    def __init__(self):
        """Initialize the graph processor"""
        self.risk_calculator = RiskCalculator()
    
    def prepare_graph_data(self, data: Asset, adjacency_matrix: List[List[int]]) -> Data:
        """
        Prepare graph data for PyTorch Geometric from asset data
        
        Args:
            data: Asset object containing components and vulnerabilities
            adjacency_matrix: Adjacency matrix representing component dependencies
            
        Returns:
            PyTorch Geometric Data object
        """
        # Calculate node features for each component
        node_features = []
        component_id_map = {}
        
        for idx, component in enumerate(data.components):
            component_id_map[component.id] = idx
            
            # Calculate CVS for the component
            cvs = self.risk_calculator.calculate_component_cvs(component.vulnerabilities)
            
            # Calculate centrality (placeholder, will be updated)
            centrality_value = 0.0
            
            # Calculate total exploit likelihood for the component
            total_exploit_likelihood = sum(
                self.risk_calculator.calculate_exploit_likelihood(vuln)
                for vuln in component.vulnerabilities
            )
            
            # Initialize risk score as placeholder - will be calculated later with proper centrality
            risk_score_placeholder = 0.0
            
            # Store node features: [CVS, centrality, risk_score_placeholder, total_exploit_likelihood]
            node_features.append([cvs, centrality_value, risk_score_placeholder, total_exploit_likelihood])
        
        # Convert to tensor
        node_features_tensor = torch.tensor(node_features, dtype=torch.float)
        
        # Build edge information from adjacency matrix
        edge_index = []
        edge_weight = []
        
        for i, row in enumerate(adjacency_matrix):
            for j, weight in enumerate(row):
                if weight > 0:
                    edge_index.append([i, j])
                    edge_weight.append(weight)
        
        # Create PyTorch Geometric Data object
        if edge_index:
            edge_index_tensor = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
            edge_weight_tensor = torch.tensor(edge_weight, dtype=torch.float)
            batch_tensor = torch.zeros(node_features_tensor.size(0), dtype=torch.long)
            adj_matrix_dense = to_dense_adj(
                edge_index_tensor, 
                batch=batch_tensor, 
                edge_attr=edge_weight_tensor
            ).squeeze(0)
        else:
            edge_index_tensor = torch.empty((2, 0), dtype=torch.long)
            edge_weight_tensor = torch.empty((0,), dtype=torch.float)
            batch_tensor = torch.zeros(node_features_tensor.size(0), dtype=torch.long)
            adj_matrix_dense = torch.zeros(
                (node_features_tensor.size(0), node_features_tensor.size(0)), 
                dtype=torch.float
            )
        
        data_obj = Data(
            x=node_features_tensor,
            edge_index=edge_index_tensor,
            edge_attr=edge_weight_tensor,
            batch=batch_tensor,
            adj=adj_matrix_dense
        )
        
        # Update centrality and recalculate risk scores
        self._update_centrality_and_risks(data_obj, data, component_id_map)
        
        return data_obj
    
    def generate_sub_graph(self, asset: Asset) -> Tuple[nx.DiGraph, Data]:
        """
        Generate a subgraph from asset data
        
        Args:
            asset: Asset object
            
        Returns:
            Tuple of (NetworkX graph, PyTorch Geometric Data object)
        """
        logger.debug(f"asset type: {type(asset)}")
        logger.debug(f"asset has {len(asset.components)} components")
        
        G = nx.DiGraph()
        node_features = []
        component_id_map = {}
        idx = 0
        
        # Create mapping from component IDs to node indices
        logger.debug(f"Creating component mapping...")
        for component in asset.components:
            component_id_map[component.id] = idx
            idx += 1
        
        logger.debug(f"Processing components...")
        # Process each component
        for component in asset.components:
            comp_idx = component_id_map[component.id]
            
            # Calculate CVS for the component
            cvs = self.risk_calculator.calculate_component_cvs(component.vulnerabilities)
            
            # Calculate total exploit likelihood
            total_exploit_likelihood = 0.0
            
            for vulnerability in component.vulnerabilities:
                # Calculate exploit likelihood and direct risk
                exploit_likelihood = self.risk_calculator.calculate_exploit_likelihood(vulnerability)
                vulnerability.exploit_likelihood = exploit_likelihood
                
                # Calculate propagation likelihood
                propagation_likelihood = self.risk_calculator.calculate_propagation_likelihood(vulnerability)
                vulnerability.propagation_likelihood = propagation_likelihood
                
                total_exploit_likelihood += exploit_likelihood
            
            # Placeholder centrality value (will be updated)
            centrality_value = 0.0
            risk_score_cvs = cvs * centrality_value
            
            # Store node features
            node_features.append([cvs, centrality_value, risk_score_cvs, total_exploit_likelihood])
            G.add_node(comp_idx)
        
        # Build edges from adjacency matrix
        edge_index = []
        edge_weight = []
        
        logger.debug(f"adjacency_matrix type: {type(asset.adjacency_matrix)}")
        logger.debug(f"adjacency_matrix length: {len(asset.adjacency_matrix) if hasattr(asset.adjacency_matrix, '__len__') else 'no length'}")
        
        for i, row in enumerate(asset.adjacency_matrix):
            for j, weight in enumerate(row):
                if weight > 0:
                    G.add_edge(i, j)
                    edge_index.append([i, j])
                    edge_weight.append(weight)
        
        if len(G.nodes) == 0:
            raise ValueError("Graph is empty after adding nodes and edges. Check the input data.")
        
        # Calculate centrality and update node features
        centrality_tensor, centrality = self.risk_calculator.calculate_centrality(G)
        
        for idx, feature in enumerate(node_features):
            feature[1] = centrality[idx]  # Update centrality value
            feature[2] = feature[0] * feature[1]  # Update risk score
            
            # Update direct risk and propagation likelihood with calculated centrality
            component_id = list(component_id_map.keys())[list(component_id_map.values()).index(idx)]
            component = next(comp for comp in asset.components if comp.id == component_id)
            
            for vulnerability in component.vulnerabilities:
                exploit_likelihood = self.risk_calculator.calculate_exploit_likelihood(vulnerability)
                # Calculate direct risk with corrected equation (3 parameters)
                direct_risk = self.risk_calculator.calculate_direct_risk(
                    exploit_likelihood, vulnerability.impact, centrality[idx]
                )
                # Store direct risk
                vulnerability.direct_risk = direct_risk
                vulnerability.exploit_likelihood = exploit_likelihood
                vulnerability.propagation_likelihood = self.risk_calculator.calculate_propagation_likelihood(vulnerability)
                

        
        # Convert to PyTorch tensors
        node_features_tensor = torch.tensor(node_features, dtype=torch.float)
        
        if edge_index:
            edge_index_tensor = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
            edge_weight_tensor = torch.tensor(edge_weight, dtype=torch.float)
            batch_tensor = torch.zeros(node_features_tensor.size(0), dtype=torch.long)
            adj_matrix_dense = to_dense_adj(
                edge_index_tensor, 
                batch=batch_tensor, 
                edge_attr=edge_weight_tensor
            ).squeeze(0)
        else:
            edge_index_tensor = torch.empty((2, 0), dtype=torch.long)
            edge_weight_tensor = torch.empty((0,), dtype=torch.float)
            batch_tensor = torch.zeros(node_features_tensor.size(0), dtype=torch.long)
            adj_matrix_dense = torch.zeros(
                (node_features_tensor.size(0), node_features_tensor.size(0)), 
                dtype=torch.float
            )
        
        data_obj = Data(
            x=node_features_tensor,
            edge_index=edge_index_tensor,
            edge_attr=edge_weight_tensor,
            batch=batch_tensor,
            adj=adj_matrix_dense
        )
        
        return G, data_obj
    
    def generate_network_graph(self, system: System) -> nx.DiGraph:
        """
        Generate a network communication graph from system data using IP addresses as nodes
        (matching old system logic)
        
        Args:
            system: System object containing assets and connections
            
        Returns:
            NetworkX directed graph representing network communication with IP nodes
        """
        import logging
        logger = logging.getLogger(__name__)
        
        main_graph = nx.DiGraph()
        
        # Add a node for the Internet (matching old system)
        internet_ip = "0.0.0.0"
        main_graph.add_node(internet_ip)
        
        # Add IP address nodes for each asset
        for asset in system.assets:
            if hasattr(asset, 'ip_address') and asset.ip_address:
                main_graph.add_node(asset.ip_address, 
                                  asset_id=asset.asset_id,
                                  asset_name=asset.name,
                                  has_vulns=any(len(comp.vulnerabilities) > 0 for comp in asset.components))
        
        # Add edges based on system connections (matching old system logic)
        if hasattr(system, 'connections') and system.connections:
            logger.info(f"Processing {len(system.connections)} system connections")
            
            for connection in system.connections:
                # Get source and destination IPs from the connection
                src_ip = connection.get('src_ip')
                dst_ip = connection.get('dst_ip')
                
                logger.info(f"Processing connection: {src_ip} -> {dst_ip}")
                
                # Add edge with weight=1.0 (matching old system)
                main_graph.add_edge(src_ip, dst_ip, weight=1.0)
        
        logger.info(f"Generated network graph with {len(main_graph.nodes())} nodes and {len(main_graph.edges())} edges")
        return main_graph
    
    def _update_centrality_and_risks(self, data_obj: Data, data: Asset, component_id_map: Dict[str, int]) -> None:
        """
        Update centrality values and recalculate risks in the data object
        
        Args:
            data_obj: PyTorch Geometric Data object
            data: Asset object
            component_id_map: Mapping from component ID to node index
        """
        # Create NetworkX graph from adjacency matrix
        G = nx.DiGraph()
        for i in range(len(data.components)):
            G.add_node(i)
        
        for i, row in enumerate(data.adjacency_matrix):
            for j, weight in enumerate(row):
                if weight > 0:
                    G.add_edge(i, j)
        
        # Calculate centrality
        centrality_tensor, centrality = self.risk_calculator.calculate_centrality(G)
        
        # Update node features with calculated centrality
        for idx in range(data_obj.x.shape[0]):
            data_obj.x[idx, 1] = centrality[idx]  # Update centrality
            data_obj.x[idx, 2] = data_obj.x[idx, 0] * centrality[idx]  # Update risk score
            
            # Update vulnerability direct risks
            component_id = list(component_id_map.keys())[list(component_id_map.values()).index(idx)]
            component = next(comp for comp in data.components if comp.id == component_id)
            
            for vulnerability in component.vulnerabilities:
                exploit_likelihood = self.risk_calculator.calculate_exploit_likelihood(vulnerability)
                # Calculate direct risk with corrected equation (3 parameters)
                direct_risk = self.risk_calculator.calculate_direct_risk(
                    exploit_likelihood, vulnerability.impact, centrality[idx]
                )
                # Store direct risk
                vulnerability.direct_risk = direct_risk
                vulnerability.exploit_likelihood = exploit_likelihood
                vulnerability.propagation_likelihood = self.risk_calculator.calculate_propagation_likelihood(vulnerability)
                


    def calculate_system_centrality(self, data: System) -> Dict[str, Any]:
        """
        Calculate system-level centrality for components and assets based on the old implementation.
        
        Args:
            data: System object containing multiple assets
            
        Returns:
            Dictionary with 'asset_centrality' and 'component_centrality' keys
        """
        try:
            # Create a directed graph for the entire system
            G = nx.DiGraph()
            
            # Add nodes for each component in each asset
            component_centrality = {}
            asset_centrality = {}
            
            for asset in data.assets:
                asset_id = asset.asset_id
                components = asset.components
                
                # Add nodes for each component
                for component in components:
                    component_name = f"A{asset_id}_{component.name}"
                    G.add_node(component_name)
                
                # Add edges based on adjacency matrix (intra-host dependencies)
                if hasattr(asset, 'adjacency_matrix') and asset.adjacency_matrix:
                    matrix = asset.adjacency_matrix
                    for i, row in enumerate(matrix):
                        for j, weight in enumerate(row):
                            if weight > 0:
                                src_component = f"A{asset_id}_{components[i].name}"
                                dst_component = f"A{asset_id}_{components[j].name}"
                                G.add_edge(src_component, dst_component, weight=weight)
            
            # Calculate centrality for the entire graph
            if len(G) > 0:
                centrality_tensor, component_centrality_dict = self.risk_calculator.calculate_centrality(G)
                
                # Convert to the expected format
                for node, centrality in component_centrality_dict.items():
                    component_centrality[node] = centrality
                
                # Aggregate centrality to compute asset centrality
                for asset in data.assets:
                    asset_id = asset.asset_id
                    components = asset.components
                    if components:
                        centrality_sum = sum(
                            component_centrality.get(f"A{asset_id}_{comp.name}", 0) 
                            for comp in components
                        )
                        asset_centrality[asset_id] = centrality_sum / len(components)
                    else:
                        asset_centrality[asset_id] = 0.0
            else:
                # Fallback if graph is empty
                for asset in data.assets:
                    asset_centrality[asset.asset_id] = 1.0
                    for component in asset.components:
                        component_name = f"A{asset.asset_id}_{component.name}"
                        component_centrality[component_name] = 1.0
            
            return {
                'asset_centrality': asset_centrality,
                'component_centrality': component_centrality
            }
            
        except Exception as e:
            print(f"Error calculating system centrality: {e}")
            # Return default values
            asset_centrality = {asset.asset_id: 1.0 for asset in data.assets}
            component_centrality = {}
            for asset in data.assets:
                for component in asset.components:
                    component_name = f"A{asset.asset_id}_{component.name}"
                    component_centrality[component_name] = 1.0
            
            return {
                'asset_centrality': asset_centrality,
                'component_centrality': component_centrality
            }


# Convenience functions for backward compatibility
def prepare_graph_data(data: Asset, adjacency_matrix: List[List[int]]) -> Data:
    """Backward compatibility function"""
    processor = GraphProcessor()
    return processor.prepare_graph_data(data, adjacency_matrix)


def generate_sub_graph(asset: Asset) -> Tuple[nx.DiGraph, Data]:
    """Backward compatibility function"""
    processor = GraphProcessor()
    return processor.generate_sub_graph(asset)


def generate_network_graph(system: System) -> nx.DiGraph:
    """Backward compatibility function"""
    processor = GraphProcessor()
    return processor.generate_network_graph(system) 