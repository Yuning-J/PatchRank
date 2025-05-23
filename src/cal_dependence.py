import networkx as nx
from data_processing import generate_sub_graph, load_system_data
from risk_calculation import calculate_centrality
import conf
import os
import json

def generate_dependence(data, scenario_id):
    with open((os.path.join(conf.asset_data_path, 'inter_dependencies.json')), 'r') as f:
        dependence_data = json.load(f)
    # Load inter-host dependencies
    inter_dependencies_key = f'inter_dependencies_{scenario_id}'
    inter_dependencies = dependence_data.get(inter_dependencies_key)

    # Create a directed graph
    G = nx.DiGraph()

    # Add nodes and intra-host dependencies from adjacency matrix
    for asset in data['Assets']:
        asset_id = asset["asset_id"]
        components = asset["components"]
        matrix = asset["adjacency_matrix"]

        # Add nodes for each component
        for component in components:
            component_name = f"A{asset_id}_{component['name']}"
            G.add_node(component_name)

        # Add edges based on adjacency matrix
        for i, row in enumerate(matrix):
            for j, weight in enumerate(row):
                if weight > 0:
                    # Determine the type of intra-host dependence based on the weight
                    if weight == 2:
                        dep_type = "ER"  # Embedding dependence
                    elif weight == 1:
                        dep_type = "SR"  # Service-related dependence

                    G.add_edge(f"A{asset_id}_{components[i]['name']}",
                               f"A{asset_id}_{components[j]['name']}",
                               weight=weight,
                               dep_type=dep_type)  # Adding dependency type for clarity

    # Add inter-host dependencies with corresponding weights
    dependency_weights = {"ER": 2, "IR": 1, "DR": 1, "SR": 1, "NR": 2, "SCR": 1}

    for src, dst, dep_type in inter_dependencies:
        G.add_edge(src, dst, weight=dependency_weights[dep_type], dep_type=dep_type)

    # Calculate centrality for the entire graph
    centrality_tensor, component_centrality = calculate_centrality(G)

    # Convert the component centrality to a dictionary
    component_centrality_dict = {node: centrality for node, centrality in component_centrality.items()}

    # Print component centrality scores
    #print("Component Centrality Scores:")
    #print(component_centrality_dict)

    # Aggregate centrality to compute asset centrality
    asset_centrality = {}
    for asset in data['Assets']:
        asset_id = asset["asset_id"]
        components = asset["components"]
        centrality_sum = sum(component_centrality[f"A{asset_id}_{comp['name']}"] for comp in components)
        asset_centrality[asset_id] = centrality_sum / len(components)

    # Print asset centrality scores
    #print("Asset Centrality Scores:")
    #for asset_id, centrality in asset_centrality.items():
    #    print(f"Asset {asset_id}: Centrality = {centrality}")

    return {'asset_centrality': asset_centrality, "component_centrality": component_centrality_dict}

# Freedy 15/09/2024 - Factoring in Classes 
from models import Vulnerability,Asset,System,Component

def generate_dependence(data, scenario_id):
    '''
    Input = System data
    Output = {assert_centrality, component_centrality_dict}
    '''
    with open((os.path.join(conf.asset_data_path, 'inter_dependencies.json')), 'r') as f:
        dependence_data = json.load(f)
    # Load inter-host dependencies
    inter_dependencies_key = f'inter_dependencies_{scenario_id}'
    inter_dependencies = dependence_data.get(inter_dependencies_key)

    # Create a directed graph
    G = nx.DiGraph()

    # Add nodes and intra-host dependencies from adjacency matrix
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
                    # Determine the type of intra-host dependence based on the weight
                    if weight == 2:
                        dep_type = "ER"  # Embedding dependence
                    elif weight == 1:
                        dep_type = "SR"  # Service-related dependence

                    G.add_edge(f"A{asset_id}_{components[i].name}",
                               f"A{asset_id}_{components[j].name}",
                               weight=weight,
                               dep_type=dep_type)  # Adding dependency type for clarity

    # Add inter-host dependencies with corresponding weights
    dependency_weights = {"ER": 2, "IR": 1, "DR": 1, "SR": 1, "NR": 2, "SCR": 1}

    for src, dst, dep_type in inter_dependencies:
        G.add_edge(src, dst, weight=dependency_weights[dep_type], dep_type=dep_type)

    # Calculate centrality for the entire graph
    centrality_tensor, component_centrality = calculate_centrality(G)

    # Convert the component centrality to a dictionary
    component_centrality_dict = {node: centrality for node, centrality in component_centrality.items()}

    # Print component centrality scores
    #print("Component Centrality Scores:")
    #print(component_centrality_dict)

    # Aggregate centrality to compute asset centrality
    asset_centrality = {}
    for asset in data.assets:
        asset_id = asset.asset_id
        components = asset.components
        centrality_sum = sum(component_centrality[f"A{asset_id}_{comp.name}"] for comp in components)
        asset_centrality[asset_id] = centrality_sum / len(components)

    # Print asset centrality scores
    #print("Asset Centrality Scores:")
    #for asset_id, centrality in asset_centrality.items():
    #    print(f"Asset {asset_id}: Centrality = {centrality}")

    return {'asset_centrality': asset_centrality, "component_centrality": component_centrality_dict}