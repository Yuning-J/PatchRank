import torch
from torch_geometric.data import Data
from torch_geometric.utils import to_dense_adj
import networkx as nx
from risk_calculation import calculate_cvs, calculate_centrality, calculate_propagation_likelihood, calculate_direct_risk, calculate_exploit_likelihood
import json

#####
### Freedy 15/09/2024 - Factoring in Classes 
#####

def load_system_data(filename):
    with open(filename, 'r') as f:
        data = json.load(f)

    # Extract and organize vulnerabilities
    vulnerabilities = []
    for asset in data.get('Assets', []):
        for component in asset.get('components', []):
            vulns = component.get('vulnerabilities', [])
            for vul in vulns:
                # Check if vulnerability is a dictionary before assigning
                if isinstance(vul, dict):
                    vul['component_id'] = component['id']
                    vul['asset_id'] = asset['asset_id']  # Link the vulnerability to the asset
                    vulnerabilities.append(vul)
                else:
                    print(f"Skipping invalid vulnerability format in component: {component['name']}")

    data['Vulnerabilities'] = vulnerabilities

    # Ensure connections are correctly structured
    connections = []
    for connection in data.get('Connections', []):
        # Validate that all necessary fields are present
        src_ip = connection.get('src_ip')
        dst_ip = connection.get('dst_ip')
        if src_ip and dst_ip:
            connections.append(connection)
    data['Connections'] = connections

    return data


def generate_sub_graph(asset):
    """
    Generate a subgraph from the asset data, calculating CVS, exploit likelihood, and direct risk for vulnerabilities.
    """
    G = nx.DiGraph()
    node_features = []
    component_id_map = {}
    idx = 0

    # Create a mapping from component IDs to node indices
    for component in asset.get('components', []):
        component_id_map[component['id']] = idx
        idx += 1

    for component in asset.get('components', []):
        comp_idx = component_id_map[component['id']]
        vulnerabilities = component.get('vulnerabilities', [])

        # Calculate CVS for the component
        CVS = calculate_cvs(vulnerabilities)

        # Placeholder for centrality value; this will be updated later
        centrality_value = 0

        # Calculate exploit likelihood and direct risk for each vulnerability
        total_exploit_likelihood = 0  # Aggregate EL for the component

        for vulnerability in vulnerabilities:
            EL_v = calculate_exploit_likelihood(vulnerability)
            direct_risk = calculate_direct_risk(EL_v, vulnerability['impact'], centrality_value)
            vulnerability['direct_risk'] = direct_risk

            # Calculate and store propagation likelihood
            PL_v = calculate_propagation_likelihood(vulnerability)
            vulnerability['propagation_likelihood'] = PL_v

            # Accumulate exploit likelihood
            total_exploit_likelihood += EL_v

        # Compute risk score using CVS and centrality placeholder
        risk_score_cvs = CVS * centrality_value

        # Include CVS-based risk scores and total exploit likelihood in node features
        node_features.append([CVS, centrality_value, risk_score_cvs, total_exploit_likelihood])
        G.add_node(comp_idx)  # Ensure nodes are added to the graph

    # Build the graph from the adjacency matrix
    adjacency_matrix = asset.get('adjacency_matrix', [])
    edge_index = []
    edge_weight = []
    for i in range(len(adjacency_matrix)):
        for j in range(len(adjacency_matrix[i])):
            if adjacency_matrix[i][j] > 0:
                G.add_edge(i, j)
                edge_index.append([i, j])
                edge_weight.append(adjacency_matrix[i][j])  # Add the weight from the adjacency matrix

    if len(G.nodes) == 0:
        raise ValueError("Graph is empty after adding nodes and edges. Check the input data.")

    # Calculate centrality and update node features with actual centrality values
    centrality_tensor, centrality = calculate_centrality(G)

    for idx, feature in enumerate(node_features):
        feature[1] = centrality[idx]  # Update centrality value
        feature[2] = feature[0] * feature[1]  # Update risk score using CVS and centrality

        # Update direct risk and propagation likelihood with calculated centrality
        component_id = list(component_id_map.keys())[list(component_id_map.values()).index(idx)]
        component_vulnerabilities = next(comp['vulnerabilities'] for comp in asset['components'] if comp['id'] == component_id)
        for vulnerability in component_vulnerabilities:
            EL_v = calculate_exploit_likelihood(vulnerability)
            vulnerability['direct_risk'] = calculate_direct_risk(EL_v, vulnerability['impact'], centrality[idx])
            vulnerability['exploit_likelihood'] = EL_v
            vulnerability['propagation_likelihood'] = calculate_propagation_likelihood(vulnerability)

    # Convert node features and edges to PyTorch tensors
    node_features_tensor = torch.tensor(node_features, dtype=torch.float)

    if len(edge_index) > 0:
        edge_index_tensor = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        edge_weight_tensor = torch.tensor(edge_weight, dtype=torch.float)
        batch_tensor = torch.zeros(node_features_tensor.size(0), dtype=torch.long)
        adj_matrix_dense = to_dense_adj(edge_index_tensor, batch=batch_tensor, edge_attr=edge_weight_tensor).squeeze(0)
    else:
        edge_index_tensor = torch.empty((2, 0), dtype=torch.long)
        edge_weight_tensor = torch.empty((0,), dtype=torch.float)
        batch_tensor = torch.zeros(node_features_tensor.size(0), dtype=torch.long)
        adj_matrix_dense = torch.zeros((node_features_tensor.size(0), node_features_tensor.size(0)), dtype=torch.float)

    data_obj = Data(x=node_features_tensor, edge_index=edge_index_tensor, edge_attr=edge_weight_tensor,
                    batch=batch_tensor, adj=adj_matrix_dense)
    return G, data_obj



def generate_network_graph(data):
    """
    Generate a network communication graph using the connection information provided in the data.

    Args:
        data (dict): The data containing asset and connection information.

    Returns:
        nx.DiGraph: A directed graph representing the network communication paths.
    """
    main_graph = nx.DiGraph()

    # Add a node for the Internet
    internet_ip = "0.0.0.0"
    main_graph.add_node(internet_ip)

    # Iterate over each connection in the data
    for connection in data['Connections']:
        src_ip = connection['src_ip']
        dst_ip = connection['dst_ip']
        main_graph.add_edge(src_ip, dst_ip, weight=1.0)  # Assuming a default weight of 1.0

    return main_graph


def print_data_obj(data_obj, data):
    """
    Print component risks, centrality values, and vulnerability-specific metrics like EL, PL, and direct risk.

    Args:
        data_obj (Data): The data object containing the graph data.
        data (dict): The original data dictionary with component and vulnerability information.
    """
    # Extract centrality and risk scores from the data object
    centrality_values = data_obj.x[:, 1]  # Assuming centrality is stored at index 1
    component_risks = data_obj.x[:, 2]  # Assuming risk score is stored at index 2

    print("Component Risks and Centrality Values:")
    for idx, component in enumerate(data['components']):
        print(f"Component ID: {component['id']}")
        print(f"  Centrality: {centrality_values[idx].item():.4f}")
        print(f"  Risk Score: {component_risks[idx].item():.4f}")

    print("\nVulnerability Details (EL, PL, Direct Risk):")
    for component in data['components']:
        print(f"Component ID: {component['id']}")
        for vul in component['vulnerabilities']:
            # Access EL, PL, and direct risk for each vulnerability
            EL_v = vul['exploit_likelihood']  # Assume these keys are set correctly
            PL_v = vul['propagation_likelihood']
            direct_risk = vul['direct_risk']

            print(f"  Vulnerability ID: {vul['cve_id']}")
            print(f"    Exploit Likelihood (EL): {EL_v:.4f}")
            print(f"    Propagation Likelihood (PL): {PL_v:.4f}")
            print(f"    Direct Risk: {direct_risk:.4f}")

    # Print the adjacency matrix
    adjacency_matrix = data_obj.adj.numpy()  # Convert PyTorch tensor to numpy array for easy printing
    print("\nAdjacency Matrix:")
    for i in range(adjacency_matrix.shape[0]):
        row = " ".join(f"{adjacency_matrix[i, j]:.0f}" for j in range(adjacency_matrix.shape[1]))
        print(row)

# Freedy 15/09/2024 - Factoring in Classes 
from models import Vulnerability,Asset,System,Component

def load_asset_data(filename: str) -> Asset:
    """
    Load asset data from a JSON file and convert it into Asset, Component, and Vulnerability objects.

    Args:
        filename (str): The path to the JSON file containing asset data.

    Returns:
        Asset: An instance of the Asset class populated with components and vulnerabilities.
    """
    with open(filename, 'r') as f:
        data = json.load(f)

    # Create the Asset object from the asset data in the file
    asset_data = data.get('asset', {})
    asset = Asset(
        asset_id=asset_data.get('id', 'Unknown'),
        asset_type=asset_data.get('type', 'Unknown'),
        name=asset_data.get('name', 'Unknown'),
        criticality_level=asset_data.get('criticality_level', 0),
        ip_address=asset_data.get('ip_address', '0.0.0.0'),
        mac_address=asset_data.get('mac_address', '00:00:00:00:00:00')
    )

    vul_list = []

    # Process components in the asset data
    for component_data in data.get('components', []):
        component = Component(
            comp_id=component_data.get('id', 'Unknown'),
            comp_type=component_data.get('type', 'Unknown'),
            vendor=component_data.get('vendor', 'Unknown'),
            name=component_data.get('name', 'Unknown'),
            version=component_data.get('version', 'Unknown'),
            embedded_in=component_data.get('embedded_in', None)
        )

        # Process vulnerabilities in each component
        for vulnerability_data in component_data.get('vulnerabilities', []):
            vulnerability = Vulnerability(
                cve_id=vulnerability_data.get('cve_id', 'Unknown'),
                cvss=vulnerability_data.get('cvss', 0.0),
                cvssV3Vector=vulnerability_data.get('cvssV3Vector', 'Unknown'),
                scopeChanged=vulnerability_data.get('scopeChanged', False),
                likelihood=vulnerability_data.get('likelihood', 0.0),
                impact=vulnerability_data.get('impact', 0.0),
                exploit=vulnerability_data.get('exploit', False),
                epss=vulnerability_data.get('epss', 0.0),
                ransomWare=vulnerability_data.get('ransomWare', False),
                component_id=component_data.get('id', 'Unknown') 
            )

            # Add vulnerability to the component
            component.add_vulnerability(vulnerability)

            # Add vulnerability to list
            vul_list.append(vulnerability)

        # Add the component to the asset
        asset.add_component(component)

    asset.vulnerabilities = vul_list

    # Process adjacency matrix if present
    adjacency_matrix = data.get('adjacency_matrix', [])
    if adjacency_matrix:
        asset.set_adjacency_matrix(adjacency_matrix)

    return asset

import json

def load_system_data(filename: str) -> System:
    # Load the JSON file
    with open(filename, 'r') as f:
        data = json.load(f)
    
    # Create an instance of the System
    system = System()

    # Loop through the assets in the JSON data
    for asset_data in data.get('Assets', []):
        asset = Asset(
            asset_id=asset_data.get('asset_id', "Unknown"),
            asset_type=asset_data.get('type', "Unknown"),
            name=asset_data.get('name', "Unknown"),
            criticality_level=asset_data.get('criticality_level', 0),
            ip_address=asset_data.get('ip_address', "0.0.0.0"),
            mac_address=asset_data.get('mac_address', "00:00:00:00:00:00")
        )

        # Loop through the components within each asset
        for component_data in asset_data.get('components', []):
            component = Component(
                comp_id=component_data.get('id', "Unknown"),
                comp_type=component_data.get('type', "Unknown"),
                vendor=component_data.get('vendor', "Unknown"),
                name=component_data.get('name', "Unknown"),
                version=component_data.get('version', "Unknown"),
                embedded_in=component_data.get('embedded_in', None)
            )

            # Loop through the vulnerabilities within each component
            for vul_data in component_data.get('vulnerabilities', []):
                vulnerability = Vulnerability(
                    cve_id=vul_data.get('cve_id', "Unknown"),
                    cvss=vul_data.get('cvss', 0.0),
                    cvssV3Vector=vul_data.get('cvssV3Vector', "Unknown"),
                    scopeChanged=vul_data.get('scopeChanged', False),
                    likelihood=vul_data.get('likelihood', 0.0),
                    impact=vul_data.get('impact', 0.0),
                    exploit=bool(vul_data.get('exploit', False)),
                    epss=vul_data.get('epss', 0.0),
                    ransomWare=bool(vul_data.get('ransomWare', False)),
                    component_id=component_data.get('id', 'Unknown')
                )

                # Add the vulnerability to the component
                component.add_vulnerability(vulnerability)

            # Add the component to the asset
            asset.add_component(component)

        # Set adjacency matrix for the asset if it exists
        adjacency_matrix = asset_data.get('adjacency_matrix', [])
        if adjacency_matrix:
            asset.set_adjacency_matrix(adjacency_matrix)

        # Add the asset to the system
        system.add_asset(asset)

    # Ensure connections are correctly structured
    connections = []
    for connection in data.get('Connections', []):
        # Validate that all necessary fields are present
        src_ip = connection.get('src_ip')
        dst_ip = connection.get('dst_ip')
        if src_ip and dst_ip:
            connections.append(connection)
    
    # Add validated connections to the system
    system.connections = connections

    return system

def prepare_graph_data(data, adjacency_matrix):
    """ 
    Prepare graph data with node features including CVS, centrality, risk scores, and exploit likelihood.
    """
    node_features = []
    edge_index = []
    edge_weight = []

    # Create a mapping from component IDs to indices
    component_id_map = {component['id']: idx for idx, component in enumerate(data['components'])}

    G = nx.DiGraph()

    for component in data['components']:
        comp_idx = component_id_map[component['id']]

        # Calculate CVS for the component
        CVS = calculate_cvs(component['vulnerabilities'])

        # Initialize centrality and risk score placeholders
        centrality_value = 0  # Placeholder, to be calculated later
        risk_score_cvs = CVS * centrality_value  # Initial placeholder for CVS-based risk score

        # Calculate and store initial direct risk, propagation likelihood, and exploit likelihood
        total_exploit_likelihood = 0  # Aggregate EL for the component

        for vulnerability in component['vulnerabilities']:
            # Calculate exploit likelihood and direct risk
            EL_v = calculate_exploit_likelihood(vulnerability)
            direct_risk = calculate_direct_risk(EL_v, vulnerability['impact'], centrality_value)

            # Store these values in the vulnerability
            vulnerability['direct_risk'] = direct_risk
            vulnerability['exploit_likelihood'] = EL_v

            # Calculate and store propagation likelihood
            PL_v = calculate_propagation_likelihood(vulnerability)
            vulnerability['propagation_likelihood'] = PL_v

            # Accumulate exploit likelihood
            total_exploit_likelihood += EL_v

        # Add CVS, risk score, and total exploit likelihood as node features
        node_features.append([CVS, centrality_value, risk_score_cvs, total_exploit_likelihood])
        G.add_node(comp_idx)  # Ensure nodes are added to the graph

    # Build the graph from the adjacency matrix
    for i in range(len(adjacency_matrix)):
        for j in range(len(adjacency_matrix[i])):
            if adjacency_matrix[i][j] > 0:
                G.add_edge(i, j)
                edge_index.append([i, j])
                edge_weight.append(adjacency_matrix[i][j])

    if len(G.nodes) == 0:
        raise ValueError("Graph is empty after adding nodes and edges. Check the input data.")

    # Calculate centrality and update node features with actual centrality values
    centrality_tensor, centrality = calculate_centrality(G)

    for idx, feature in enumerate(node_features):
        feature[1] = centrality[idx]  # Update centrality value
        feature[2] = feature[0] * feature[1]  # Update CVS-based risk score with calculated centrality

        # Update direct risk with calculated centrality
        component_id = list(component_id_map.keys())[list(component_id_map.values()).index(idx)]
        component_vulnerabilities = next(
            comp['vulnerabilities'] for comp in data['components'] if comp['id'] == component_id)
        for vulnerability in component_vulnerabilities:
            EL_v = calculate_exploit_likelihood(vulnerability)
            vulnerability['direct_risk'] = calculate_direct_risk(EL_v, vulnerability['impact'], centrality[idx])
            vulnerability['exploit_likelihood'] = EL_v

    # Convert node features and edges to PyTorch tensors
    node_features_tensor = torch.tensor(node_features, dtype=torch.float)
    edge_index_tensor = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
    edge_weight_tensor = torch.tensor(edge_weight, dtype=torch.float)
    batch_tensor = torch.zeros(node_features_tensor.size(0), dtype=torch.long)
    adj_matrix_dense = to_dense_adj(edge_index_tensor, batch=batch_tensor, edge_attr=edge_weight_tensor).squeeze(0)

    # Return the prepared data object
    return Data(x=node_features_tensor, edge_index=edge_index_tensor, edge_attr=edge_weight_tensor, batch=batch_tensor,
                adj=adj_matrix_dense)

def prepare_graph_data(data, adjacency_matrix):
    """ 
    Prepare graph data with node features including CVS, centrality, risk scores, and exploit likelihood.
    Input: <Asset>
    """
    node_features = []
    edge_index = []
    edge_weight = []

    # Create a mapping from component IDs to indices
    component_id_map = {component.id: idx for idx, component in enumerate(data.components)}

    G = nx.DiGraph()

    for component in data.components:
        comp_idx = component_id_map[component.id]

        # Calculate CVS for the component
        CVS = calculate_cvs(component.vulnerabilities)

        # Initialize centrality and risk score placeholders
        centrality_value = 0  # Placeholder, to be calculated later
        risk_score_cvs = CVS * centrality_value  # Initial placeholder for CVS-based risk score

        # Calculate and store initial direct risk, propagation likelihood, and exploit likelihood
        total_exploit_likelihood = 0  # Aggregate EL for the component

        for vulnerability in component.vulnerabilities:
            # Calculate exploit likelihood and direct risk
            EL_v = calculate_exploit_likelihood(vulnerability)
            direct_risk = calculate_direct_risk(EL_v, vulnerability.impact, centrality_value)

            # Store these values in the vulnerability
            vulnerability.direct_risk = direct_risk
            vulnerability.exploit_likelihood = EL_v

            # Calculate and store propagation likelihood
            PL_v = calculate_propagation_likelihood(vulnerability)
            vulnerability.propagation_likelihood = PL_v

            # Accumulate exploit likelihood
            total_exploit_likelihood += EL_v

        # Add CVS, risk score, and total exploit likelihood as node features
        node_features.append([CVS, centrality_value, risk_score_cvs, total_exploit_likelihood])
        G.add_node(comp_idx)  # Ensure nodes are added to the graph

    # Build the graph from the adjacency matrix
    for i in range(len(adjacency_matrix)):
        for j in range(len(adjacency_matrix[i])):
            if adjacency_matrix[i][j] > 0:
                G.add_edge(i, j)
                edge_index.append([i, j])
                edge_weight.append(adjacency_matrix[i][j])

    if len(G.nodes) == 0:
        raise ValueError("Graph is empty after adding nodes and edges. Check the input data.")

    # Calculate centrality and update node features with actual centrality values
    centrality_tensor, centrality = calculate_centrality(G)

    for idx, feature in enumerate(node_features):
        feature[1] = centrality[idx]  # Update centrality value
        feature[2] = feature[0] * feature[1]  # Update CVS-based risk score with calculated centrality

        # Update direct risk with calculated centrality
        component_id = list(component_id_map.keys())[list(component_id_map.values()).index(idx)]
        component_vulnerabilities = next(
            comp.vulnerabilities for comp in data.components if comp.id == component_id)
        for vulnerability in component_vulnerabilities:
            EL_v = calculate_exploit_likelihood(vulnerability)
            vulnerability.direct_risk = calculate_direct_risk(EL_v, vulnerability.impact, centrality[idx])
            vulnerability.exploit_likelihood = EL_v

    # Convert node features and edges to PyTorch tensors
    node_features_tensor = torch.tensor(node_features, dtype=torch.float)
    edge_index_tensor = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
    edge_weight_tensor = torch.tensor(edge_weight, dtype=torch.float)
    batch_tensor = torch.zeros(node_features_tensor.size(0), dtype=torch.long)
    adj_matrix_dense = to_dense_adj(edge_index_tensor, batch=batch_tensor, edge_attr=edge_weight_tensor).squeeze(0)

    # Return the prepared data object
    return Data(x=node_features_tensor, edge_index=edge_index_tensor, edge_attr=edge_weight_tensor, batch=batch_tensor,
                adj=adj_matrix_dense)

def generate_sub_graph(asset):
    """
    Generate a subgraph from the asset data, calculating CVS, exploit likelihood, and direct risk for vulnerabilities.
    Input: <Asset>
    """
    G = nx.DiGraph()
    node_features = []
    component_id_map = {}
    idx = 0

    # Create a mapping from component IDs to node indices
    for component in asset.components:
        component_id_map[component.id] = idx
        idx += 1

    for component in asset.components:
        comp_idx = component_id_map[component.id]
        vulnerabilities = component.vulnerabilities

        # Calculate CVS for the component
        CVS = calculate_cvs(vulnerabilities)

        # Placeholder for centrality value; this will be updated later
        centrality_value = 0

        # Calculate exploit likelihood and direct risk for each vulnerability
        total_exploit_likelihood = 0  # Aggregate EL for the component

        for vulnerability in vulnerabilities:
            EL_v = calculate_exploit_likelihood(vulnerability)
            direct_risk = calculate_direct_risk(EL_v, vulnerability.impact, centrality_value)
            vulnerability.direct_risk = direct_risk

            # Calculate and store propagation likelihood
            PL_v = calculate_propagation_likelihood(vulnerability)
            vulnerability.propagation_likelihood = PL_v

            # Accumulate exploit likelihood
            total_exploit_likelihood += EL_v

        # Compute risk score using CVS and centrality placeholder
        risk_score_cvs = CVS * centrality_value

        # Include CVS-based risk scores and total exploit likelihood in node features
        node_features.append([CVS, centrality_value, risk_score_cvs, total_exploit_likelihood])
        G.add_node(comp_idx)  # Ensure nodes are added to the graph

    # Build the graph from the adjacency matrix
    adjacency_matrix = asset.adjacency_matrix
    edge_index = []
    edge_weight = []
    for i in range(len(adjacency_matrix)):
        for j in range(len(adjacency_matrix[i])):
            if adjacency_matrix[i][j] > 0:
                G.add_edge(i, j)
                edge_index.append([i, j])
                edge_weight.append(adjacency_matrix[i][j])  # Add the weight from the adjacency matrix

    if len(G.nodes) == 0:
        raise ValueError("Graph is empty after adding nodes and edges. Check the input data.")

    # Calculate centrality and update node features with actual centrality values
    centrality_tensor, centrality = calculate_centrality(G)

    for idx, feature in enumerate(node_features):
        feature[1] = centrality[idx]  # Update centrality value
        feature[2] = feature[0] * feature[1]  # Update risk score using CVS and centrality

        # Update direct risk and propagation likelihood with calculated centrality
        component_id = list(component_id_map.keys())[list(component_id_map.values()).index(idx)]
        component_vulnerabilities = next(comp.vulnerabilities for comp in asset.components if comp.id == component_id)
        for vulnerability in component_vulnerabilities:
            EL_v = calculate_exploit_likelihood(vulnerability)
            vulnerability.direct_risk = calculate_direct_risk(EL_v, vulnerability.impact, centrality[idx])
            vulnerability.exploit_likelihood = EL_v
            vulnerability.propagation_likelihood = calculate_propagation_likelihood(vulnerability)

    # Convert node features and edges to PyTorch tensors
    node_features_tensor = torch.tensor(node_features, dtype=torch.float)

    if len(edge_index) > 0:
        edge_index_tensor = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        edge_weight_tensor = torch.tensor(edge_weight, dtype=torch.float)
        batch_tensor = torch.zeros(node_features_tensor.size(0), dtype=torch.long)
        adj_matrix_dense = to_dense_adj(edge_index_tensor, batch=batch_tensor, edge_attr=edge_weight_tensor).squeeze(0)
    else:
        edge_index_tensor = torch.empty((2, 0), dtype=torch.long)
        edge_weight_tensor = torch.empty((0,), dtype=torch.float)
        batch_tensor = torch.zeros(node_features_tensor.size(0), dtype=torch.long)
        adj_matrix_dense = torch.zeros((node_features_tensor.size(0), node_features_tensor.size(0)), dtype=torch.float)

    data_obj = Data(x=node_features_tensor, edge_index=edge_index_tensor, edge_attr=edge_weight_tensor,
                    batch=batch_tensor, adj=adj_matrix_dense)
    return G, data_obj

def generate_network_graph(data):
    """
    Generate a network communication graph using the connection information provided in the data.

    Args:
        Class <Asset>

    Returns:
        nx.DiGraph: A directed graph representing the network communication paths.
    """
    main_graph = nx.DiGraph()

    # Add a node for the Internet
    internet_ip = "0.0.0.0"
    main_graph.add_node(internet_ip)

    # Iterate over each connection in the data
    for connection in data.connections:
        src_ip = connection['src_ip']
        dst_ip = connection['dst_ip']
        main_graph.add_edge(src_ip, dst_ip, weight=1.0)  # Assuming a default weight of 1.0

    return main_graph

def print_data_obj(data_obj, data):
    """
    Print component risks, centrality values, and vulnerability-specific metrics like EL, PL, and direct risk.

    Args:
        data_obj (Data): The data object containing the graph data.
        data (dict): The original data dictionary with component and vulnerability information.
        Input: <Asset>
    """
    # Extract centrality and risk scores from the data object
    centrality_values = data_obj.x[:, 1]  # Assuming centrality is stored at index 1
    component_risks = data_obj.x[:, 2]  # Assuming risk score is stored at index 2

    print("Component Risks and Centrality Values:")
    for idx, component in enumerate(data.components):
        print(f"Component ID: {component.id}")
        print(f"  Centrality: {centrality_values[idx].item():.4f}")
        print(f"  Risk Score: {component_risks[idx].item():.4f}")

    print("\nVulnerability Details (EL, PL, Direct Risk):")
    for component in data['components']:
        print(f"Component ID: {component.id}")
        for vul in component.vulnerabilities:
            # Access EL, PL, and direct risk for each vulnerability
            EL_v = vul.exploit  # Assume these keys are set correctly
            PL_v = vul.propagation_likelihood
            direct_risk = vul.direct_risk

            print(f"  Vulnerability ID: {vul.cve_id}")
            print(f"    Exploit Likelihood (EL): {EL_v:.4f}")
            print(f"    Propagation Likelihood (PL): {PL_v:.4f}")
            print(f"    Direct Risk: {direct_risk:.4f}")

    # Print the adjacency matrix
    adjacency_matrix = data_obj.adj.numpy()  # Convert PyTorch tensor to numpy array for easy printing
    print("\nAdjacency Matrix:")
    for i in range(adjacency_matrix.shape[0]):
        row = " ".join(f"{adjacency_matrix[i, j]:.0f}" for j in range(adjacency_matrix.shape[1]))
        print(row)
