import argparse
import os
import time
import conf
from data_processing import (
    prepare_graph_data,
    load_asset_data,
    load_system_data,
    generate_sub_graph,
    generate_network_graph,
    print_data_obj,
)
from risk_calculation import (
    calculate_risk,
    recalculate_asset_criticality,
)
from patch_prioritization import (
    rank_patches,
    verify_risk_reduction,
    rank_vulnerabilities_by_cvss
)
from graph_visualization import (
    visualize_results_asset,
    visualize_network_graph,
)
from cal_dependence import(
    generate_dependence
)
import torch
import numpy as np


def main():
    '''
    Script calling example: 
    python main.py --level system --data system_data.json --cvss_only
    python main.py --level asset --data asset_data.json --cvss_only
    Note that you can set up the data access in ./src/conf.py
    --level : default Asset
    --data : Compulsory filename. Data must be in conf.asset_vul_data_path
    --cvss_only : default False. This is for component vulnerability ranking based solely on CVSS base scores
    '''

    parser = argparse.ArgumentParser(description="Asset/System-Level Vulnerability Ranking")
    parser.add_argument(
        "--level",
        choices=["asset", "system"],
        default="asset",
        help="Choose the level of analysis: 'asset' or 'system'",
    )
    parser.add_argument(
        "--data",
        required= True,
        help="Path to the data file",
    )
    parser.add_argument(
    "--cvss_only",
    action="store_true",
    help="Rank vulnerabilities based on CVSS base scores only",
)
    args = parser.parse_args()

    start_time = time.time()

    if args.cvss_only:
        if args.level == "asset":
            data = load_asset_data(os.path.join(conf.asset_vul_data_path, args.data))
        elif args.level == 'system':
            data = load_system_data(os.path.join(conf.asset_vul_data_path, args.data))
        
        rank_vulnerabilities_by_cvss(data, level=args.level)
        return

    # Asset level Analysis
    if args.level == "asset":
        # Load and prepare data
        data = load_asset_data(os.path.join(conf.asset_vul_data_path, args.data))
        adjacency_matrix = np.array(data.adjacency_matrix)
        data_obj = prepare_graph_data(data, adjacency_matrix)

        # Calculate initial risks
        initial_cvs, initial_centrality, initial_component_risks, initial_asset_risk = calculate_risk(
            data, data_obj = data_obj, level = 'asset'
        )
        print(f'Initial Asset Risk: {initial_asset_risk:.4f}')
        print(f'Initial Component Risks: {initial_component_risks}')
        #print(f'Initial Component CVS: {initial_cvs}')
        #print(f'Component Centrality: {initial_centrality}')

        # Rank patches
        patch_rankings = rank_patches(
            data,
            adjacency_matrix = adjacency_matrix,
            initial_risk = initial_asset_risk,
            level = 'asset'
            )
        #verify_risk_reduction(patch_rankings, initial_asset_risk, level= 'asset')

        # Visualize results
        with torch.no_grad():
            visualize_results_asset(data, data_obj, adjacency_matrix, initial_component_risks)

    # System level analysis
    elif args.level == "system":
        data = load_system_data(os.path.join(conf.asset_vul_data_path, args.data))
        scenario_id = args.data.split('_')[1].split('.')[0]

        # Generate asset and component centrality values from generate_dependenceG.py
        centrality_dict = generate_dependence(data, scenario_id)
        sys_comp_centrality = centrality_dict['component_centrality']
        asset_centrality_provided = centrality_dict['asset_centrality']

        # Generate sub-graphs, calculate risks, and connect them based on network communication
        asset_sub_graphs = {}
        asset_centrality = {}  # To store asset centrality scores

        # Assign provided centrality values once, outside the loop
        for asset in data.assets:
            asset_id = asset.asset_id
            asset_centrality[asset_id] = asset_centrality_provided.get(asset_id, 0)  # Default to 0 if not provided

        for asset in data.assets:
            # Generate subgraph and calculate component centrality for the asset
            G, data_obj = generate_sub_graph(asset)
            _, asset_comp_centrality, _, total_propagated_risk = calculate_risk(asset, 
                                                                                data_obj= data_obj,
                                                                                level= 'asset')

            # Store the subgraph and calculated risks
            asset_sub_graphs[asset.name] = {
                'graph': G,
                'data_obj': data_obj,
                'total_propagated_risk': total_propagated_risk
            }

            # Store total propagated risk in the asset data
            asset.total_propagated_risk = total_propagated_risk

        # Recalculate asset criticality using the function
        updated_criticality, final_criticality = recalculate_asset_criticality(data.assets, asset_centrality)

        # Update the criticality levels in the data structure
        for asset in data.assets:
            asset_id = asset.asset_id
            asset.updated_criticality = updated_criticality[asset_id]
            asset.final_criticality = final_criticality[asset_id]  # Replace with the new criticality

        # Print updated asset risks and criticality
        for asset in data.assets:
            print(f"Asset: {asset.name}, Total Risk: {total_propagated_risk}, Centrality: {asset_centrality[asset.asset_id]}, "
                  f"Criticality: {asset.updated_criticality}, Integer Criticality: {asset.final_criticality}")


        # Generate network communication graph
        main_graph = generate_network_graph(data)
        print("Main Network Graph Connections:")
        for edge in main_graph.edges:
            print(f"{edge[0]} -> {edge[1]}")

        # Calculate system-level risk score using the recalculated asset criticality and risks
        initial_system_risk = calculate_risk(data,
                                             level= 'system',
                                             G = main_graph, comp_centrality_data= sys_comp_centrality)
        print(f"Initial System-level Risk Score: {initial_system_risk}")

        # Rank patches
        patch_rankings = rank_patches(
            data, level = 'system',
             initial_risk = initial_system_risk, 
             main_graph=main_graph, 
             comp_centrality_data= sys_comp_centrality)
        print(
            'Patch Rankings (Vulnerability ID, Risk Reduction, Patched Asset Risk, CVSS, Exploit, Component, Likelihood, Impact, ScopeChanged):')
        for patch in patch_rankings:
            print(patch)

      
        #verify_risk_reduction(patch_rankings, initial_system_risk, level= 'system')

        end_time = time.time()  # End the clock
        elapsed_time = end_time - start_time  # Calculate the elapsed time
        print(f"Elapsed time: {elapsed_time:.2f} seconds")  # Print the elapsed time


if __name__ == "__main__":
    main()
