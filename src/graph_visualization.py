import matplotlib.pyplot as plt
import networkx as nx
from torch_geometric.utils import to_networkx
from matplotlib.colors import Normalize
import matplotlib.cm as cm
import os
import conf

def plot_component_risks(component_risks, component_ids):
    plt.figure(figsize=(10, 6))
    plt.bar(component_ids, component_risks, color='skyblue')
    plt.xlabel('Component ID')
    plt.ylabel('Risk Score')
    plt.title('Component Risks')
    plt.savefig(os.path.join(conf.output_path, 'component_risks.png'))  # Save the component risks plot
    plt.show()

def visualize_graph_asset(data_obj, component_risks, data):
    G = nx.DiGraph()  # Directed graph

    num_components = len(data['components'])
    max_risk = max(component_risks)
    min_risk = min(component_risks)

    node_colors = []
    node_labels = {}
    edge_colors = []
    edge_styles = []
    edge_weights = []

    node_index = 0
    vul_node_index = num_components

    for component in data['components']:
        normalized_risk = (component_risks[node_index] - min_risk) / (max_risk - min_risk)
        node_colors.append(normalized_risk)
        node_labels[node_index] = f"Comp {component['id']}\n {component['name']+ component['version']} \nCVS: {data_obj.x[node_index][0]:.2f}\nCentrality: {data_obj.x[node_index][1]:.2f}"

        for vul in component['vulnerabilities']:
            G.add_node(vul_node_index)
            node_colors.append(1.0)  # Red color for vulnerabilities
            node_labels[vul_node_index] = f"Vul {vul['cve_id']}\nCVSS: {vul['cvss']:.2f}\nExploits: {vul['exploit']}\nScopeChanged: {vul['scopeChanged']}\nRansomware: {vul['ransomWare']}"
            G.add_edge(node_index, vul_node_index)  # Connect component to its vulnerability
            edge_colors.append('green')
            edge_styles.append('solid')
            edge_weights.append(1.0)
            vul_node_index += 1

        node_index += 1

    # Add edges from adjacency matrix
    adjacency_matrix = data['adjacency_matrix']
    for i in range(num_components):
        for j in range(num_components):
            if adjacency_matrix[i][j] > 0:
                G.add_edge(j, i)
                edge_colors.append('blue' if adjacency_matrix[i][j] == 1 else 'red')
                edge_styles.append('solid' if adjacency_matrix[i][j] == 1 else 'dotted')
                edge_weights.append(1.0)

    # Adjust the layout for better node separation (increase `k` for more spread)
    pos = nx.spring_layout(G, seed=42, k=0.75, iterations=50)  # Increase `k` to spread nodes further apart

    plt.figure(figsize=(20, 15))  # Increased figure size for better separation

    # Draw component nodes first
    nodes = nx.draw_networkx_nodes(G, pos, nodelist=range(num_components), node_color=node_colors[:num_components],
                                   node_size=1200, cmap=plt.cm.viridis)
    nodes.set_norm(plt.Normalize(vmin=0, vmax=1))  # Normalize the colormap for component nodes

    # Draw vulnerability nodes as triangles
    nx.draw_networkx_nodes(G, pos, nodelist=range(num_components, len(G.nodes)), node_color='red', node_shape='^', node_size=1200)

    # Offset labels to avoid overlaps
    label_pos = {k: (v[0], v[1] + 0.05) for k, v in pos.items()}  # Small y-offset for labels

    # Draw labels
    nx.draw_networkx_labels(G, label_pos, labels=node_labels, font_size=8)  # Reduced font size for clarity

    # Draw edges with arrows on top
    nx.draw_networkx_edges(G, pos, edgelist=[(u, v) for u, v in G.edges if u < num_components and v < num_components],
                           edge_color='blue', style='solid', width=1.0, arrows=True, arrowstyle='-|>', arrowsize=20)
    nx.draw_networkx_edges(G, pos, edgelist=[(u, v) for u, v in G.edges if u >= num_components or v >= num_components],
                           edge_color='green', style='solid', width=1.0, arrows=True, arrowstyle='-|>', arrowsize=20)

    sm = plt.cm.ScalarMappable(cmap=plt.cm.viridis, norm=plt.Normalize(vmin=0, vmax=1))
    sm.set_array([])
    plt.colorbar(sm, ax=plt.gca(), label='Normalized Component Risk Scores')
    plt.title('Graph Visualization with Component and Vulnerability Nodes')
    plt.savefig(os.path.join(conf.output_path, 'graph_visualization.png'))  # Save the graph visualization
    plt.show()

def visualize_results_asset(data, data_obj, adjacency_matrix, component_risks):
    component_ids = [component['id'] for component in data['components']]

    plot_component_risks(component_risks, component_ids)
    visualize_graph_asset(data_obj, component_risks, data)

def visualize_entire_system(data, component_risks_dict):
    G = nx.DiGraph()  # Directed graph

    node_colors = []
    node_labels = {}
    edge_colors = []
    edge_styles = []
    edge_weights = []

    # Add nodes and edges for each asset and its components
    for asset in data['Assets']:
        asset_id = asset['asset_id']
        asset_name = asset['name']
        G.add_node(f"Asset_{asset_id}", risk=asset['criticality_level'], label=f"{asset_name}\nCriticality: {asset['criticality_level']}")
        node_colors.append(asset['criticality_level'] / 10)  # Normalize to [0, 1]
        node_labels[f"Asset_{asset_id}"] = f"{asset_name}\nCriticality: {asset['criticality_level']}"

        for component in asset['components']:
            component_id = component['id']
            component_key = f"Asset_{asset_id}_Comp_{component_id}"
            component_risk = component_risks_dict.get(component_key, 0)
            G.add_node(component_key, risk=component_risk, label=f"Comp {component_id}\nRisk: {component_risk:.2f}")
            node_colors.append(component_risk / 10)  # Normalize to [0, 1]
            node_labels[component_key] = f"Comp {component_id}\nRisk: {component_risk:.2f}"

            # Connect asset to its components
            G.add_edge(f"Asset_{asset_id}", component_key)
            edge_colors.append('black')
            edge_styles.append('solid')
            edge_weights.append(1.0)

            # Connect components based on the adjacency matrix
            for i, row in enumerate(asset['adjacency_matrix']):
                for j, value in enumerate(row):
                    if value > 0:
                        src_component_key = f"Asset_{asset_id}_Comp_{i + 1}"
                        dst_component_key = f"Asset_{asset_id}_Comp_{j + 1}"
                        G.add_edge(src_component_key, dst_component_key)
                        edge_colors.append('blue')
                        edge_styles.append('dotted')
                        edge_weights.append(value)

    # Connect assets based on their network communication layer
    for asset in data['Assets']:
        src_ip = asset['network_communication_layer']['src_ip']
        dst_ip = asset['network_communication_layer']['dst_ip']
        for other_asset in data['Assets']:
            if other_asset['network_communication_layer']['src_ip'] == dst_ip:
                G.add_edge(f"Asset_{asset['asset_id']}", f"Asset_{other_asset['asset_id']}")
                edge_colors.append('red')
                edge_styles.append('dashed')
                edge_weights.append(1.0)

    # Adjust the layout for better node separation
    pos = nx.spring_layout(G, seed=42)  # Use spring layout for better node separation

    plt.figure(figsize=(20, 15))

    # Draw nodes first
    nodes = nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=1000, cmap=plt.cm.viridis)
    nodes.set_norm(plt.Normalize(vmin=0, vmax=1))  # Normalize the colormap for nodes
    nx.draw_networkx_labels(G, pos, labels=node_labels)

    # Draw edges with arrows on top
    nx.draw_networkx_edges(G, pos, edge_color=edge_colors, style=edge_styles, width=edge_weights, arrows=True, arrowstyle='-|>', arrowsize=20)

    sm = plt.cm.ScalarMappable(cmap=plt.cm.viridis, norm=plt.Normalize(vmin=0, vmax=1))
    sm.set_array([])
    plt.colorbar(sm, ax=plt.gca(), label='Normalized Risk Scores')

    plt.title('Comprehensive Network Graph Visualization')
    plt.savefig(os.path.join(conf.output_path, 'comprehensive_graph_visualization.png'))  # Save the graph visualization
    plt.show()


def visualize_network_graph(graph):
    """
    Visualize the network communication graph using matplotlib with enhanced features.

    Args:
        graph (nx.DiGraph): The directed graph to visualize.
        output_path (str): Path to save the visualized graph image.
    """
    plt.figure(figsize=(12, 10))  # Set the figure size larger for better visibility

    # Create a layout for the nodes
    pos = nx.kamada_kawai_layout(graph)  # A layout that might be better for complex graphs

    # Draw nodes with different colors based on the criticality level or other criteria
    node_colors = ['skyblue' if 'type' in graph.nodes[n] and graph.nodes[n]['type'] == 'Web Server' else 'lightgreen' for n in graph]

    # Draw the nodes
    nx.draw_networkx_nodes(graph, pos, node_size=700, node_color=node_colors, edgecolors='black')

    # Draw the edges with width proportional to the 'weight' attribute
    edge_widths = [graph[u][v]['weight'] * 0.5 for u, v in graph.edges()]
    nx.draw_networkx_edges(graph, pos, width=edge_widths, arrowstyle='-|>', arrowsize=10, edge_color='gray')

    # Draw the node labels
    nx.draw_networkx_labels(graph, pos, font_size=8, font_family='sans-serif')

    # Optionally, draw edge labels if needed
    edge_labels = nx.get_edge_attributes(graph, 'weight')
    if edge_labels:
        nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_labels, font_color='red')

    # Set the plot title and turn off the axis
    plt.title('Enhanced Network Communication Graph Visualization')
    plt.axis('off')
    # Save the graph to a file
    plt.savefig(os.path.join(conf.output_path, 'network_communication_graph.png'))
    plt.show()


def visualize_results_system(data, component_risks_dict):
    visualize_entire_system(data, component_risks_dict)

def visualize_graph(data_obj, component_risks, data):
    G = nx.DiGraph()  # Directed graph

    num_components = len([comp for asset in data['Assets'] for comp in asset['components']])
    max_risk = max(component_risks)
    min_risk = min(component_risks)

    node_colors = []
    node_labels = {}
    edge_colors = []
    edge_styles = []
    edge_weights = []

    pos = {}
    cluster_offset = 0
    cluster_spacing = 10
    cluster_y_offset = 5

    node_index = 0
    vul_node_index = num_components

    for asset_index, asset in enumerate(data['Assets']):
        asset_pos_x = cluster_offset
        asset_pos_y = cluster_y_offset
        components = asset['components']
        for component in components:
            if node_index < len(component_risks):
                normalized_risk = (component_risks[node_index] - min_risk) / (max_risk - min_risk)
                G.add_node(node_index, risk=normalized_risk, label=f"Comp {component['id']}\nRisk: {component_risks[node_index]:.2f}")
                node_colors.append(normalized_risk)
                node_labels[node_index] = f"Comp {component['id']}\nRisk: {component_risks[node_index]:.2f}"
                pos[node_index] = (asset_pos_x, asset_pos_y)
                asset_pos_y += 1

                for vul in component['vulnerabilities']:
                    G.add_node(vul_node_index, risk=1.0, label=f"Vul {vul['cve_id']}\nCVSS: {vul['cvss']:.2f}\nExploits: {vul['exploit']}", shape='^')
                    node_colors.append(1.0)  # Red color for vulnerabilities
                    node_labels[vul_node_index] = f"Vul {vul['cve_id']}\nCVSS: {vul['cvss']:.2f}\nExploits: {vul['exploit']}"
                    pos[vul_node_index] = (asset_pos_x + 1, asset_pos_y)
                    G.add_edge(node_index, vul_node_index)  # Connect component to its vulnerability
                    edge_colors.append('green')
                    edge_styles.append('solid')
                    edge_weights.append(1.0)
                    vul_node_index += 1

                node_index += 1
        cluster_offset += cluster_spacing

    # Add edges from adjacency matrices
    component_index_offset = 0
    for asset in data['Assets']:
        adjacency_matrix = asset['adjacency_matrix']
        num_asset_components = len(asset['components'])
        for i in range(num_asset_components):
            for j in range(num_asset_components):
                if adjacency_matrix[i][j] > 0:
                    G.add_edge(i + component_index_offset, j + component_index_offset)
                    edge_colors.append('blue' if adjacency_matrix[i][j] == 1 else 'red')
                    edge_styles.append('solid' if adjacency_matrix[i][j] == 1 else 'dotted')
                    edge_weights.append(1.0)
        component_index_offset += num_asset_components

    plt.figure(figsize=(20, 15))

    cmap = plt.cm.viridis
    norm = Normalize(vmin=0, vmax=1)

    # Draw component nodes
    nodes = nx.draw_networkx_nodes(G, pos, nodelist=range(num_components), node_color=node_colors[:num_components],
                                   node_size=1000, cmap=cmap)
    nodes.set_norm(norm)

    # Draw vulnerability nodes as triangles
    vul_nodes = nx.draw_networkx_nodes(G, pos, nodelist=range(num_components, len(G.nodes)), node_color='red', node_size=1000, node_shape='^')

    nx.draw_networkx_labels(G, pos, labels=node_labels)

    # Draw edges with arrows on top
    nx.draw_networkx_edges(G, pos, edgelist=[(u, v) for u, v in G.edges if u < num_components and v < num_components],
                           edge_color=edge_colors, style=edge_styles, width=1.0, arrows=True, arrowstyle='-|>', arrowsize=20)
    nx.draw_networkx_edges(G, pos, edgelist=[(u, v) for u, v in G.edges if u >= num_components or v >= num_components],
                           edge_color='green', style='solid', width=1.0, arrows=True, arrowstyle='-|>', arrowsize=20)

    sm = plt.cm.ScalarMappable(cmap=cmap, norm=norm)
    sm.set_array([])
    plt.colorbar(sm, ax=plt.gca(), label='Normalized Component Risk Scores')
    for asset_index, asset in enumerate(data['Assets']):
        plt.text(cluster_offset - cluster_spacing / 2, cluster_y_offset - 2, asset['name'], fontsize=12, ha='center')
    plt.title('Comprehensive Network Graph Visualization')
    plt.savefig(os.path.join(conf.output_path, 'comprehensive_graph_visualization.png'))  # Save the graph visualization
    #plt.show()

def visualize_results(data, data_obj, component_risks):
    component_ids = [component['id'] for asset in data['Assets'] for component in asset['components']]

    #plot_component_risks(component_risks, component_ids)
    visualize_graph(data_obj, component_risks, data)

# Freedy 15/09/2024 - Factoring in Classes 
from models import Vulnerability,Asset,System,Component

def visualize_results_asset(data, data_obj, adjacency_matrix, component_risks):
    component_ids = [component.id for component in data.components]

    plot_component_risks(component_risks, component_ids)
    visualize_graph_asset(data_obj, component_risks, data)

def visualize_graph_asset(data_obj, component_risks, data):
    G = nx.DiGraph()  # Directed graph

    num_components = len(data.components)
    max_risk = max(component_risks)
    min_risk = min(component_risks)

    node_colors = []
    node_labels = {}
    edge_colors = []
    edge_styles = []
    edge_weights = []

    node_index = 0
    vul_node_index = num_components

    for component in data.components:
        normalized_risk = (component_risks[node_index] - min_risk) / (max_risk - min_risk)
        node_colors.append(normalized_risk)
        node_labels[node_index] = f"Comp {component.id}\n {component.name + component.version} \nCVS: {data_obj.x[node_index][0]:.2f}\nCentrality: {data_obj.x[node_index][1]:.2f}"

        for vul in component.vulnerabilities:
            G.add_node(vul_node_index)
            node_colors.append(1.0)  # Red color for vulnerabilities
            node_labels[vul_node_index] = f"Vul {vul.cve_id}\nCVSS: {vul.cvss:.2f}\nExploits: {vul.exploit}\nScopeChanged: {vul.scopeChanged}\nRansomware: {vul.ransomWare}"
            G.add_edge(node_index, vul_node_index)  # Connect component to its vulnerability
            edge_colors.append('green')
            edge_styles.append('solid')
            edge_weights.append(1.0)
            vul_node_index += 1

        node_index += 1

    # Add edges from adjacency matrix
    adjacency_matrix = data.adjacency_matrix
    for i in range(num_components):
        for j in range(num_components):
            if adjacency_matrix[i][j] > 0:
                G.add_edge(j, i)
                edge_colors.append('blue' if adjacency_matrix[i][j] == 1 else 'red')
                edge_styles.append('solid' if adjacency_matrix[i][j] == 1 else 'dotted')
                edge_weights.append(1.0)

    # Adjust the layout for better node separation (increase `k` for more spread)
    pos = nx.spring_layout(G, seed=42, k=0.75, iterations=50)  # Increase `k` to spread nodes further apart

    plt.figure(figsize=(20, 15))  # Increased figure size for better separation

    # Draw component nodes first
    nodes = nx.draw_networkx_nodes(G, pos, nodelist=range(num_components), node_color=node_colors[:num_components],
                                   node_size=1200, cmap=plt.cm.viridis)
    nodes.set_norm(plt.Normalize(vmin=0, vmax=1))  # Normalize the colormap for component nodes

    # Draw vulnerability nodes as triangles
    nx.draw_networkx_nodes(G, pos, nodelist=range(num_components, len(G.nodes)), node_color='red', node_shape='^', node_size=1200)

    # Offset labels to avoid overlaps
    label_pos = {k: (v[0], v[1] + 0.05) for k, v in pos.items()}  # Small y-offset for labels

    # Draw labels
    nx.draw_networkx_labels(G, label_pos, labels=node_labels, font_size=8)  # Reduced font size for clarity

    # Draw edges with arrows on top
    nx.draw_networkx_edges(G, pos, edgelist=[(u, v) for u, v in G.edges if u < num_components and v < num_components],
                           edge_color='blue', style='solid', width=1.0, arrows=True, arrowstyle='-|>', arrowsize=20)
    nx.draw_networkx_edges(G, pos, edgelist=[(u, v) for u, v in G.edges if u >= num_components or v >= num_components],
                           edge_color='green', style='solid', width=1.0, arrows=True, arrowstyle='-|>', arrowsize=20)

    sm = plt.cm.ScalarMappable(cmap=plt.cm.viridis, norm=plt.Normalize(vmin=0, vmax=1))
    sm.set_array([])
    plt.colorbar(sm, ax=plt.gca(), label='Normalized Component Risk Scores')
    plt.title('Graph Visualization with Component and Vulnerability Nodes')
    plt.savefig(os.path.join(conf.output_path, 'graph_visualization.png'))  # Save the graph visualization
    plt.show()