"""
Graph Utilities for Multi-Path Network Risk Analysis
Implements k-shortest paths algorithm for Task 1.3 as specified in revision.md
"""

import heapq
from typing import Dict, List, Tuple, Set, Any, Optional
import logging
import networkx as nx
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PathInfo:
    """Information about a path in the attack graph"""
    path: List[str]
    length: float
    probability: float
    risk: float
    edges: List[Tuple[str, str]]


class GraphUtils:
    """Utilities for attack graph analysis and k-shortest paths"""
    
    def __init__(self):
        self.graph = None
        
    def set_graph(self, graph: nx.DiGraph) -> None:
        """Set the attack graph for analysis"""
        self.graph = graph
    
    def k_shortest_paths(self, source: str, target: str, k: int = 3) -> List[PathInfo]:
        """
        Find k-shortest paths between source and target nodes
        
        Args:
            source: Source node ID
            target: Target node ID  
            k: Number of shortest paths to find (default 3 as per revision.md)
            
        Returns:
            List of PathInfo objects representing k-shortest paths
        """
        if not self.graph:
            raise ValueError("Graph not set. Call set_graph() first.")
            
        if source not in self.graph.nodes or target not in self.graph.nodes:
            logger.warning(f"Source {source} or target {target} not in graph")
            return []
            
        # Use Yen's algorithm for k-shortest paths
        paths = self._yens_k_shortest_paths(source, target, k)
        
        # Convert to PathInfo objects with probability and risk calculations
        path_infos = []
        for path_nodes, length in paths:
            edges = [(path_nodes[i], path_nodes[i+1]) for i in range(len(path_nodes)-1)]
            probability = self._calculate_path_probability(edges)
            risk = self._calculate_path_risk(edges, probability)
            
            path_info = PathInfo(
                path=path_nodes,
                length=length,
                probability=probability,
                risk=risk,
                edges=edges
            )
            path_infos.append(path_info)
            
        logger.debug(f"Found {len(path_infos)} paths from {source} to {target}")
        return path_infos
    
    def add_vertical_escalation_edges(self, hosts: List[str], 
                                    hypervisors: List[str],
                                    gpus: List[str]) -> None:
        """
        Add vertical escalation edges to the graph as specified in Task 1.3a
        
        Args:
            hosts: List of host node IDs
            hypervisors: List of hypervisor node IDs
            gpus: List of GPU node IDs
        """
        if not self.graph:
            raise ValueError("Graph not set. Call set_graph() first.")
            
        # Add host → hypervisor edges
        for host in hosts:
            for hypervisor in hypervisors:
                if host in self.graph.nodes and hypervisor in self.graph.nodes:
                    # Check if host is managed by hypervisor (simplified heuristic)
                    if self._host_managed_by_hypervisor(host, hypervisor):
                        self.graph.add_edge(host, hypervisor, 
                                          edge_type='vertical_escalation',
                                          escalation_type='host_to_hypervisor',
                                          base_probability=0.3)  # Configurable
                        
        # Add GPU → OS edges  
        for gpu in gpus:
            for host in hosts:
                if gpu in self.graph.nodes and host in self.graph.nodes:
                    # Check if GPU is on host
                    if self._gpu_on_host(gpu, host):
                        self.graph.add_edge(gpu, host,
                                          edge_type='vertical_escalation', 
                                          escalation_type='gpu_to_os',
                                          base_probability=0.4)  # Configurable
                        
        logger.info(f"Added vertical escalation edges: {len(hosts)}→{len(hypervisors)} hosts, "
                   f"{len(gpus)}→{len(hosts)} GPUs")
    
    def calculate_network_risk(self, vulnerable_assets: List[str], 
                             source_assets: List[str] = None,
                             k: int = 3) -> Dict[str, Any]:
        """
        Calculate network risk using k-shortest paths as per Equation in EquationReferences.md
        
        Args:
            vulnerable_assets: List of assets with vulnerabilities
            source_assets: List of potential attack source assets (if None, uses all)
            k: Number of shortest paths to consider
            
        Returns:
            Dictionary with network risk analysis results
        """
        if not self.graph:
            raise ValueError("Graph not set. Call set_graph() first.")
            
        if source_assets is None:
            # Use all nodes as potential sources
            source_assets = list(self.graph.nodes)
            
        network_risk_data = {
            'total_risk': 0.0,
            'asset_risks': {},
            'path_details': [],
            'k_paths_used': k
        }
        
        # Calculate risk for each vulnerable asset
        for target_asset in vulnerable_assets:
            asset_risk = 0.0
            asset_paths = []
            
            # Find k-shortest paths from each source to this target
            for source_asset in source_assets:
                if source_asset == target_asset:
                    continue
                    
                paths = self.k_shortest_paths(source_asset, target_asset, k)
                
                for path_info in paths:
                    # Network risk contribution: Prob(P) * Risk(P)
                    risk_contribution = path_info.probability * path_info.risk
                    asset_risk += risk_contribution
                    
                    asset_paths.append({
                        'source': source_asset,
                        'target': target_asset,
                        'path': path_info.path,
                        'probability': path_info.probability,
                        'risk': path_info.risk,
                        'contribution': risk_contribution
                    })
            
            network_risk_data['asset_risks'][target_asset] = asset_risk
            network_risk_data['path_details'].extend(asset_paths)
            network_risk_data['total_risk'] += asset_risk
            
        logger.info(f"Calculated network risk: {network_risk_data['total_risk']:.4f} "
                   f"for {len(vulnerable_assets)} assets using {k}-shortest paths")
        
        return network_risk_data
    
    def _yens_k_shortest_paths(self, source: str, target: str, k: int) -> List[Tuple[List[str], float]]:
        """
        Yen's algorithm for k-shortest paths
        
        Returns:
            List of (path_nodes, path_length) tuples
        """
        if source == target:
            return [([source], 0.0)]
            
        # Find the shortest path
        try:
            shortest_path = nx.shortest_path(self.graph, source, target, weight='weight')
            shortest_length = nx.shortest_path_length(self.graph, source, target, weight='weight')
        except nx.NetworkXNoPath:
            return []
            
        # Initialize
        A = [(shortest_path, shortest_length)]  # Shortest paths found
        B = []  # Candidate paths
        
        for i in range(1, k):
            if not A:
                break
                
            # The spurious path is the last path in A
            spurious_path = A[i-1][0]
            
            # For each node in the spurious path except the target
            for j in range(len(spurious_path) - 1):
                spur_node = spurious_path[j]
                root_path = spurious_path[:j+1]
                
                # Remove edges that are part of previous shortest paths
                removed_edges = []
                for path, _ in A:
                    if len(path) > j and path[:j+1] == root_path:
                        if j+1 < len(path):
                            edge = (path[j], path[j+1])
                            if self.graph.has_edge(*edge):
                                edge_data = self.graph[edge[0]][edge[1]]
                                self.graph.remove_edge(*edge)
                                removed_edges.append((*edge, edge_data))
                
                # Calculate the spur path from spur_node to target
                try:
                    spur_path = nx.shortest_path(self.graph, spur_node, target, weight='weight')
                    spur_length = nx.shortest_path_length(self.graph, spur_node, target, weight='weight')
                    
                    # Entire path is root_path + spur_path (excluding duplicate spur_node)
                    total_path = root_path[:-1] + spur_path
                    total_length = (shortest_length if j == 0 else 
                                  nx.shortest_path_length(self.graph, source, spur_node, weight='weight')) + spur_length
                    
                    # Add to candidate paths if not already found
                    if (total_path, total_length) not in A and (total_path, total_length) not in B:
                        B.append((total_path, total_length))
                        
                except nx.NetworkXNoPath:
                    pass
                
                # Restore removed edges
                for edge_data in removed_edges:
                    self.graph.add_edge(edge_data[0], edge_data[1], **edge_data[2])
            
            if not B:
                break
                
            # Sort B by path length and add shortest to A
            B.sort(key=lambda x: x[1])
            A.append(B.pop(0))
        
        return A[:k]
    
    def _calculate_path_probability(self, edges: List[Tuple[str, str]]) -> float:
        """
        Calculate probability of path as product of edge probabilities and mitigation factors
        Implements: Prob(P) = ∏ ( EL(e) * MF(e) ) for edges e in path
        """
        probability = 1.0
        
        for edge in edges:
            if self.graph.has_edge(*edge):
                edge_data = self.graph[edge[0]][edge[1]]
                
                # Get exploit likelihood for this edge  
                exploit_likelihood = edge_data.get('exploit_likelihood', 0.5)
                
                # Get mitigation factor for this edge
                mitigation_factor = edge_data.get('mitigation_factor', 1.0)
                
                # Multiply by edge probability
                edge_prob = exploit_likelihood * mitigation_factor
                probability *= edge_prob
            else:
                logger.warning(f"Edge {edge} not found in graph")
                probability *= 0.1  # Default low probability for missing edges
                
        return probability
    
    def _calculate_path_risk(self, edges: List[Tuple[str, str]], probability: float) -> float:
        """
        Calculate risk contribution of a path
        Risk(P) considers aggregated impact of path
        """
        # Aggregate impact along the path
        total_impact = 0.0
        
        for edge in edges:
            if self.graph.has_edge(*edge):
                edge_data = self.graph[edge[0]][edge[1]]
                impact = edge_data.get('impact_score', 1.0)
                total_impact += impact
            else:
                total_impact += 0.5  # Default impact for missing edges
        
        # Risk is probability weighted by impact
        return probability * total_impact
    
    def _host_managed_by_hypervisor(self, host: str, hypervisor: str) -> bool:
        """Check if host is managed by hypervisor (simplified heuristic)"""
        # Simplified logic - in practice would check asset relationships
        host_data = self.graph.nodes.get(host, {})
        hypervisor_data = self.graph.nodes.get(hypervisor, {})
        
        # Check if they're in same subnet or cluster
        host_subnet = host_data.get('subnet', '')
        hypervisor_subnet = hypervisor_data.get('subnet', '')
        
        return host_subnet == hypervisor_subnet and host_subnet != ''
    
    def _gpu_on_host(self, gpu: str, host: str) -> bool:
        """Check if GPU is on host (simplified heuristic)"""
        # Simplified logic - in practice would check hardware relationships  
        gpu_data = self.graph.nodes.get(gpu, {})
        host_data = self.graph.nodes.get(host, {})
        
        # Check if GPU belongs to host
        gpu_host = gpu_data.get('host', '')
        return gpu_host == host


def create_attack_graph_with_verticals(assets: List[Dict[str, Any]]) -> nx.DiGraph:
    """
    Create attack graph with vertical escalation edges
    
    Args:
        assets: List of asset dictionaries with metadata
        
    Returns:
        NetworkX DiGraph with vertical escalation edges added
    """
    graph = nx.DiGraph()
    
    # Add nodes for each asset
    hosts = []
    hypervisors = []
    gpus = []
    
    for asset in assets:
        asset_id = asset['id']
        asset_type = asset.get('type', 'unknown')
        
        graph.add_node(asset_id, **asset)
        
        # Categorize assets for vertical edges
        if asset_type == 'host' or asset_type == 'server':
            hosts.append(asset_id)
        elif asset_type == 'hypervisor':
            hypervisors.append(asset_id) 
        elif asset_type == 'gpu':
            gpus.append(asset_id)
    
    # Add horizontal edges (network connections)
    for asset in assets:
        asset_id = asset['id']
        connections = asset.get('connections', [])
        
        for connection in connections:
            if connection in graph.nodes:
                # Add edge with default weights
                graph.add_edge(asset_id, connection,
                             edge_type='network',
                             exploit_likelihood=0.3,
                             mitigation_factor=1.0,
                             impact_score=1.0,
                             weight=1.0)
    
    # Add vertical escalation edges using GraphUtils
    utils = GraphUtils()
    utils.set_graph(graph)
    utils.add_vertical_escalation_edges(hosts, hypervisors, gpus)
    
    logger.info(f"Created attack graph with {graph.number_of_nodes()} nodes, "
               f"{graph.number_of_edges()} edges (including vertical escalation)")
    
    return graph