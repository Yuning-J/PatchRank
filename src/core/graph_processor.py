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
            cvs = self.risk_calculator.calculate_cvs(component.vulnerabilities)
            
            # Calculate centrality (placeholder, will be updated)
            centrality_value = 0.0
            
            # Calculate total exploit likelihood for the component
            total_exploit_likelihood = sum(
                self.risk_calculator.calculate_exploit_likelihood(vuln)
                for vuln in component.vulnerabilities
            )
            
            # Calculate risk score using CVS and centrality
            risk_score_cvs = cvs * centrality_value
            
            # Store node features: [CVS, centrality, risk_score, total_exploit_likelihood]
            node_features.append([cvs, centrality_value, risk_score_cvs, total_exploit_likelihood])
        
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
        G = nx.DiGraph()
        node_features = []
        component_id_map = {}
        idx = 0
        
        # Create mapping from component IDs to node indices
        for component in asset.components:
            component_id_map[component.id] = idx
            idx += 1
        
        # Process each component
        for component in asset.components:
            comp_idx = component_id_map[component.id]
            
            # Calculate CVS for the component
            cvs = self.risk_calculator.calculate_cvs(component.vulnerabilities)
            
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
                vulnerability.direct_risk = self.risk_calculator.calculate_direct_risk(
                    exploit_likelihood, vulnerability.impact, centrality[idx]
                )
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
        Generate a network communication graph from system data
        
        Args:
            system: System object containing assets and connections
            
        Returns:
            NetworkX directed graph representing network communication
        """
        main_graph = nx.DiGraph()
        
        # Add a node for the Internet
        internet_ip = "0.0.0.0"
        main_graph.add_node(internet_ip)
        
        # Add edges from connections
        for connection in system.connections:
            src_ip = connection.get('src_ip')
            dst_ip = connection.get('dst_ip')
            if src_ip and dst_ip:
                main_graph.add_edge(src_ip, dst_ip, weight=1.0)
        
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
                vulnerability.direct_risk = self.risk_calculator.calculate_direct_risk(
                    exploit_likelihood, vulnerability.impact, centrality[idx]
                )
                vulnerability.exploit_likelihood = exploit_likelihood
                vulnerability.propagation_likelihood = self.risk_calculator.calculate_propagation_likelihood(vulnerability)


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