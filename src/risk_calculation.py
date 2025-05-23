import torch
import numpy as np
import networkx as nx

def calculate_centrality(G):
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

    max_centrality = max(centrality.values())
    for node in centrality:
        centrality[node] /= max_centrality

    centrality_tensor = torch.tensor([centrality[node] for node in G.nodes()], dtype=torch.float32).unsqueeze(1)
    return centrality_tensor, centrality

def calculate_propagation_likelihood(vulnerability, delta=0.5, theta=0.5):
    """
    Calculate the propagation likelihood using scope change and ransomware indicators.
    """
    scope_change_contribution = delta * calculate_scope_change(vulnerability)
    ransomware_contribution = theta * calculate_ransomware(vulnerability)

    # Sum weighted components to get overall propagation likelihood
    return scope_change_contribution + ransomware_contribution

def calculate_direct_risk(exploit_likelihood, impact, centrality):
    """
    Calculate the direct risk for a given vulnerability on a component.
    """
    return exploit_likelihood * impact * centrality

def normalize_risks(asset_risks, scale=10, epsilon=0.01):
    mean_risk = np.mean(asset_risks)
    std_dev_risk = np.std(asset_risks) if np.std(asset_risks) != 0 else 1  # Avoid division by zero

    # Calculate Z-scores
    z_scores = [(risk - mean_risk) / std_dev_risk for risk in asset_risks]

    # Min-max normalization on Z-scores to scale to (0, 10)
    min_z = min(z_scores)
    max_z = max(z_scores)
    range_z = max_z - min_z if max_z != min_z else 1  # Avoid division by zero

    # Adjust the range to ensure values fall strictly within (0, 10)
    adjusted_scale = scale - 2 * epsilon

    normalized_risks = [((z - min_z) / range_z) * adjusted_scale + epsilon for z in z_scores]

    # Ensure no values are exactly 0 or 10
    normalized_risks = [max(min(risk, scale - epsilon), epsilon) for risk in normalized_risks]

    return normalized_risks

def propagate_risk_bfs(data_obj, vulnerabilities):
    """
    Calculate propagated risks using a BFS approach based on direct risk and propagation likelihood.
    """
    adjacency_matrix = data_obj.adj.numpy()  # Ensure adjacency matrix is correctly shaped and converted to numpy
    components = [{'risk_cvs': data_obj.x[i, 2].item(), 'centrality': data_obj.x[i, 1].item()} for i in range(data_obj.x.shape[0])]

    def bfs(start_idx, PL_v, S_impact):
        indirect_risk = 0  # Start with zero indirect risk
        queue = [(start_idx, 0)]  # Initialize queue with cumulative weight as 0 for summation
        visited = set()
        while queue:
            current_idx, cumulative_weight = queue.pop(0)
            #print("current cumulative weight: ", cumulative_weight)
            if current_idx not in visited:
                visited.add(current_idx)
                #print(f"Visiting component {current_idx + 1}, cumulative weight: {cumulative_weight}")
                for neighbor_idx in range(len(components)):
                    if adjacency_matrix[neighbor_idx, current_idx] > 0 and neighbor_idx not in visited:
                        edge_weight = adjacency_matrix[neighbor_idx, current_idx]
                        new_cumulative_weight = cumulative_weight + edge_weight  # Sum the path weights
                        indirect_risk += edge_weight * S_impact  # Add the edge impact to the indirect risk
                        #print(f"Component {neighbor_idx + 1} impacted by Component {current_idx + 1} with cumulative weight: {new_cumulative_weight}")
                        queue.append((neighbor_idx, new_cumulative_weight))
        indirect_risk *= PL_v  # Scale the total indirect risk by the propagation likelihood
        indirect_risk = round(indirect_risk, 5)
        #print(f"Total indirect risk for component: {indirect_risk}\n")
        return indirect_risk

    total_propagated_risks = []

    for vulnerability in vulnerabilities:
        component_idx = vulnerability['component_id'] - 1  # Assuming component_id is 1-based
        direct_risk = vulnerability['direct_risk']
        S_impact = vulnerability['impact']
        PL_v = vulnerability['propagation_likelihood']
        #print(f"Direct risk for component {component_idx + 1} due to vulnerability {vulnerability['cve_id']}: {direct_risk}")

        # Calculate indirect risk, only propagate if PL_v >= 0.5
        if PL_v >= 0.5:
            indirect_risk = bfs(component_idx, PL_v, S_impact)
            R_vulnerability = direct_risk + indirect_risk
        else:
            R_vulnerability = direct_risk
        #print(f"Total risk for vulnerability {vulnerability['cve_id']}: {R_vulnerability}\n")
        total_propagated_risks.append(R_vulnerability)
    return total_propagated_risks

def normalize_business_criticality_rule_based(criticality_level):
    # Define a rule-based mapping for business criticality
    rule_based_mapping = {
        1: 0.1,
        2: 0.3,
        3: 0.5,
        4: 0.7,
        5: 0.9,
        6: 1.0
    }
    return rule_based_mapping.get(criticality_level, 0.1)  # Default to 0.1 if not found

def calculate_cvs(vulnerabilities):
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

def calculate_exploit_likelihood(vulnerability, alpha=0.3, beta=0.4, gamma=0.3):
    # Normalize CVSS likelihood to a 0-1 range
    normalized_cvss = vulnerability.likelihood / 10.0

    # Ensure epss is a float
    epss = float(vulnerability.epss)

    # Weighted contributions
    cvss_exploitability = alpha * normalized_cvss
    epss_contribution = beta * epss
    exploit_contribution = gamma * vulnerability.exploit

    # Sum weighted components to get overall exploit likelihood
    return cvss_exploitability + epss_contribution + exploit_contribution

def calculate_scope_change(vulnerability):
    """
    Determine if a vulnerability results in a scope change.
    """
    return 1 if vulnerability.scopeChanged else 0

def calculate_ransomware(vulnerability):
    """
    Determine if a vulnerability has been used in ransomware attacks.
    """
    return vulnerability.ransomWare

def recalculate_asset_criticality(assets_data, centrality_data):
    final_criticality = {}
    updated_criticality = {}

    for asset in assets_data:
        asset_id = asset.asset_id
        business_criticality = asset.criticality_level
        normalized_centrality = centrality_data.get(asset_id, 0)  # Directly use the already normalized centrality

        # Apply rule-based normalization for business criticality
        normalized_business_criticality = normalize_business_criticality_rule_based(business_criticality)

        # Combine normalized values using a weighted sum (adjust the weights if necessary)
        combined_criticality = 0.4 * normalized_business_criticality + 0.6 * normalized_centrality
        updated_criticality[asset_id] = combined_criticality

        # Convert to integer final criticality between 0 and 10
        integer_final_criticality = int(combined_criticality * 10)
        final_criticality[asset_id] = integer_final_criticality

    return updated_criticality, final_criticality


def identify_critical_assets(data, threshold=6):
    critical_assets = [asset for asset in data.assets if asset.final_criticality >= threshold]
    print(f"Critical Assets: {[asset.name for asset in critical_assets]}")
    return critical_assets

def calculate_shortest_paths(main_graph, critical_assets):
    critical_ips = [asset.ip_address for asset in critical_assets]
    shortest_paths = {}
    visited_edges = set()  # Track visited edges (segments) to combine paths
    internet_ip = "0.0.0.0"

    for dst_ip in critical_ips:
        try:
            print('hi')
            print(main_graph)
            print(dst_ip)
            path = nx.shortest_path(main_graph, source=internet_ip, target=dst_ip, weight='weight')

            # Check for overlaps with previously visited edges and merge paths
            merged_path = []
            for i in range(len(path) - 1):
                src_ip = path[i]
                dst_ip = path[i + 1]
                edge = (src_ip, dst_ip)

                # If edge is already visited, skip adding it to merged_path
                if edge in visited_edges:
                    continue

                # Add edge to merged_path and mark as visited
                merged_path.append(src_ip)
                visited_edges.add(edge)

            # Ensure the last node (dst_ip) is added to merged_path
            if merged_path and merged_path[-1] != dst_ip:
                merged_path.append(dst_ip)

            # Update shortest_paths dictionary
            if merged_path:
                shortest_paths[(internet_ip, dst_ip)] = merged_path

        except nx.NetworkXNoPath:
            continue  # Skip if no path is found

    return shortest_paths

def calculate_network_risk(path, data, component_centrality):
    path_risk = 0
    #print("\nCalculating Network Risk for Path:")

    for ip in path:
        asset = next((a for a in data.assets if a.ip_address == ip), None)
        if asset:
            #print(f"Asset: {asset['name']} (IP: {ip})")

            for component in asset.components:
                component_name = f"A{asset.asset_id}_{component.name}"
                component_centrality_value = component_centrality.get(component_name, 0)

                for vulnerability in component.vulnerabilities:
                    if classify_vulnerability(vulnerability) == "Network-based":
                        # Calculate exploit likelihood using the provided function
                        exploit_likelihood = calculate_exploit_likelihood(vulnerability)

                        # Calculate risk using the centrality value from the loaded data
                        propagation_risk = exploit_likelihood * vulnerability.impact * component_centrality_value
                        path_risk += propagation_risk

                        # Print the contribution of the vulnerability to the network risk
                        #print(f"  Vulnerability: {vulnerability['cve_id']}")
                        #print(f"  Network Propagation Risk Contribution: {propagation_risk}\n")
    #print(f"Total Network Risk for Path: {path_risk}\n")
    return path_risk

def classify_vulnerability(vulnerability):
    cvss_vector = vulnerability.cvssV3Vector
    # Extract the Attack Vector (AV) from the CVSS vector
    if "/AV:N" in cvss_vector:
        return "Network-based"
    elif "/AV:A" in cvss_vector:
        return "Network-based"
    elif "/AV:L" in cvss_vector:
        return "Host-based"
    elif "/AV:P" in cvss_vector:
        return "Host-based"
    else:
        return "Unknown"

def calculate_risk(data, data_obj=None, level="asset", G=None, comp_centrality_data=None, criticality_threshold=6):
    """
    Unified function to calculate the risk for both asset and system levels.
    
    Parameters:
    - data: The input data containing assets or components.
    - data_obj: The object containing component data (used for asset-level calculations).
    - level: Either 'asset' or 'system' to distinguish the calculation mode.
    - G: The system graph (used for system-level calculations).
    - comp_centrality_data: Centrality data for system-level calculations.
    - criticality_threshold: Threshold to identify critical assets in system-level calculations.
    
    Returns:
    - Risk for each component (or asset) and total risk (propagated or system-level).
    """
    if level == "asset":
        # Asset-level risk calculation (similar to calculate_asset_risk)
        component_cvs = [{'risk': data_obj.x[i, 0].item()} for i in range(data_obj.x.shape[0])]
        component_centrality = [{'risk': data_obj.x[i, 1].item()} for i in range(data_obj.x.shape[0])]
        component_risks_cvs = [{'risk': data_obj.x[i, 2].item()} for i in range(data_obj.x.shape[0])]

        all_vulnerabilities = []
        for component in data.components:
            for vulnerability in component.vulnerabilities:
                all_vulnerabilities.append({
                    'component_id': vulnerability.component_id,
                    'cvss': vulnerability.cvss,
                    'likelihood': vulnerability.likelihood,
                    'impact': vulnerability.impact,
                    'exploit': vulnerability.exploit,
                    'epss': vulnerability.epss,
                    'cve_id': vulnerability.cve_id,
                    'scopeChanged': vulnerability.scopeChanged,
                    'ransomWare': vulnerability.ransomWare,
                    'direct_risk': vulnerability.direct_risk,
                    'propagation_likelihood': vulnerability.propagation_likelihood
                })

        # Calculate propagated risks using direct risk and propagation likelihood
        propagated_risks = propagate_risk_bfs(data_obj, all_vulnerabilities)
        total_propagated_risk = sum(propagated_risks)

        # Return the risks for each component (based on CVS) and the total propagated risk
        return ([comp['risk'] for comp in component_cvs],
                [comp['risk'] for comp in component_centrality],
                [comp['risk'] for comp in component_risks_cvs],
                total_propagated_risk)

    elif level == "system":
        # System-level risk calculation (similar to calculate_system_risk)
        critical_assets = identify_critical_assets(data, criticality_threshold)
        shortest_paths = calculate_shortest_paths(G, critical_assets)

        network_risk = 0
        host_risk = 0
        included_assets = set()

        for asset in data.assets:
            if asset.ip_address not in included_assets:
                asset_criticality = float(asset.updated_criticality)
                asset_host_risk = asset_criticality * asset.total_propagated_risk
                host_risk += asset_host_risk
                included_assets.add(asset.ip_address)

        # Calculate network-based risk by iterating through the shortest paths
        for (src_ip, dst_ip), path in shortest_paths.items():
            path_risk = calculate_network_risk(path, data, comp_centrality_data)
            network_risk += path_risk
            path_ips = ' -> '.join(path)
            print(f"Shortest path from {src_ip} to {dst_ip}: {path_ips} with network risk: {path_risk}")

        # Combine host-based and network-based risks to get the system-level risk
        system_risk = host_risk + network_risk

        print(f"Total Host-based Risk: {host_risk}")
        print(f"Total Network-based Risk: {network_risk}")
        print(f"System-level Risk: {system_risk}")

        return system_risk

def calculate_asset_risk(data, data_obj):
    """
    Calculate the risk for each component based on CVS and the total propagated risk.
    """
    # Extract CVS-based risk for each component
    component_cvs = [{'risk': data_obj.x[i, 0].item()} for i in range(data_obj.x.shape[0])]
    component_centrality = [{'risk': data_obj.x[i, 1].item()} for i in range(data_obj.x.shape[0])]
    component_risks_cvs = [{'risk': data_obj.x[i, 2].item()} for i in range(data_obj.x.shape[0])]

    all_vulnerabilities = []
    for component in data.components:
        for vulnerability in component.vulnerabilities:
            all_vulnerabilities.append({
                'component_id': vulnerability.component_id,
                'cvss': vulnerability.cvss,
                'likelihood': vulnerability.likelihood,
                'impact': vulnerability.impact,
                'exploit': vulnerability.exploit,
                'epss': vulnerability.epss,
                'cve_id': vulnerability.cve_id,
                'scopeChanged': vulnerability.scopeChanged,
                'ransomWare': vulnerability.ransomWare,
                'direct_risk': vulnerability.direct_risk,
                'propagation_likelihood': vulnerability.propagation_likelihood
            })

    # Calculate propagated risks using direct risk and propagation likelihood
    propagated_risks = propagate_risk_bfs(data_obj, all_vulnerabilities)
    total_propagated_risk = sum(propagated_risks)

    # Return the risks for each component (based on CVS) and the total propagated risk
    return ([comp['risk'] for comp in component_cvs],
            [comp['risk'] for comp in component_centrality],
            [comp['risk'] for comp in component_risks_cvs],
            total_propagated_risk)

def calculate_system_risk(G, data, comp_centrality_data, criticality_threshold=6):
    """
    Calculate the system-level risk by aggregating host-based and network-based risks separately.
    """
    # Identify critical assets after recalculating criticality
    critical_assets = identify_critical_assets(data, criticality_threshold)
    shortest_paths = calculate_shortest_paths(G, critical_assets)

    # Initialize system risk components
    network_risk = 0
    host_risk = 0
    included_assets = set()  # Track which assets have been included in the host-based risk calculation

    # Calculate host-based risk using calculate_asset_risk function
    for asset in data.assets:
        if asset.ip_address not in included_assets:
            #asset_host_risk, _, _, _ = calculate_asset_risk(asset)  # Assuming calculate_asset_risk returns the total host-based risk
            #host_risk += asset_host_risk
            asset_criticality = float(asset.updated_criticality)  # Assuming final_criticality is already computed
            asset_host_risk = asset_criticality * asset.total_propagated_risk
            host_risk += asset_host_risk
            included_assets.add(asset.ip_address)

    # Calculate network-based risk by iterating through the shortest paths
    for (src_ip, dst_ip), path in shortest_paths.items():
        path_risk = calculate_network_risk(path, data, comp_centrality_data)
        network_risk += path_risk
        path_ips = ' -> '.join(path)
        print(f"Shortest path from {src_ip} to {dst_ip}: {path_ips} with network risk: {path_risk}")

    # Combine host-based and network-based risks to get the system-level risk
    system_risk = host_risk + network_risk

    print(f"Total Host-based Risk: {host_risk}")
    print(f"Total Network-based Risk: {network_risk}")
    print(f"System-level Risk: {system_risk}")

    return system_risk
