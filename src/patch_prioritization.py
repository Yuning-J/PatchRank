from itertools import combinations
import copy
from copy import deepcopy
import numpy as np
from data_processing import prepare_graph_data, load_asset_data, generate_sub_graph
#from train_and_test import calculate_risk_scores, calculate_risk_scores_verification
from risk_calculation import calculate_asset_risk, normalize_risks, calculate_system_risk
from models import Vulnerability

def verify_risk_reduction(patch_rankings,initial_risk,level= 'asset'):
    if level == 'asset':
        for patch in patch_rankings:
            vuln_id, risk_reduction, patched_asset_risk, cvss, exploit, component_id, likelihood, impact, scopeChanged, ransomWare, epss = patch
            print(f"Checking vulnerability {vuln_id} in component {component_id} with CVSS {cvss} and existing exploits {exploit}")
            print(f"Initial risks: {initial_risk}")
            print(f"Patched risks: {patched_asset_risk}")
            assert patched_asset_risk < initial_risk, f"Total Risk did not decrease for vulnerability {vuln_id}"
        print("All patches lead to a reduction in the calculated risks (total, propagated, and GNN predicted).")
    elif level =='system':
        for patch in patch_rankings:
            vuln_id, risk_reduction, patched_system_risk, cvss, exploit, component_id, asset_name, likelihood, impact, scopeChanged, ransomWare, epss = patch
            print(
                f"Checking vulnerability {vuln_id} in component {component_id} (Asset: {asset_name}) with CVSS {cvss} and existing exploits {exploit}")
            print(f"Initial risks: {initial_risk}")
            print(f"Patched risks: {patched_system_risk}")
            assert patched_system_risk < initial_risk, f"System Risk did not decrease for vulnerability {vuln_id}"
        print("All patches lead to a reduction in the calculated system risks.")

def rank_vulnerabilities_by_cvss(data, level='asset'):
    """
    Rank vulnerabilities based on CVSS base scores only.
    
    Parameters:
    - data: A System or Asset-level dataset containing vulnerabilities
    - level: Either 'asset' or 'system', determines how to process the data
    """

    # List to hold vulnerabilities with CVSS score
    vulnerabilities_with_cvss = []

    # Process asset-level vulnerabilities
    if level == 'asset' or level == 'system':
        for asset in data['Assets']:
            for component in asset['components']:
                for vulnerability in component['vulnerabilities']:
                    # Check if vulnerability is a dictionary
                    if isinstance(vulnerability, dict):
                        if vulnerability.get('cvss', None) is not None:
                            vulnerabilities_with_cvss.append({
                                'cve_id': vulnerability['cve_id'],
                                'cvss': vulnerability['cvss'],
                                'asset': asset['name'],
                                'component': component['name'],
                                'component_id': component['id'],
                            })
                    else:
                        # Skip and print a warning if vulnerability format is invalid
                        print(f"Skipping invalid vulnerability format in component: {component['name']} (asset: {asset['name']})")

    # Sort vulnerabilities based on CVSS score (highest to lowest)
    ranked_vulnerabilities = sorted(vulnerabilities_with_cvss, key=lambda x: x['cvss'], reverse=True)

    # Print the ranked vulnerabilities
    print("\nRanked Vulnerabilities by CVSS Score:")
    for idx, vulnerability in enumerate(ranked_vulnerabilities, start=1):
        print(f"{idx}. CVE ID: {vulnerability['cve_id']} | CVSS Score: {vulnerability['cvss']} | Asset: {vulnerability['asset']} | Component: {vulnerability['component']} (ID: {vulnerability['component_id']})")
    
    return ranked_vulnerabilities

#####
### Freedy 15/09/2024 - Factoring in Classes 
#####

def rank_patches(data, initial_risk, level = 'asset', main_graph = None, comp_centrality_data = None, adjacency_matrix = None):
    patch_effectiveness = []

    if level == 'asset': # <Asset>
        for comp_idx, component in enumerate(data.components):
            for vul_idx, vulnerability in enumerate(component.vulnerabilities):
                patched_data = simulate_patch_asset(data, comp_idx, vul_idx)
                patched_data_obj = prepare_graph_data(patched_data, adjacency_matrix)
                initial_cvs, initial_centrality, patched_component_risks, patched_asset_risk = calculate_asset_risk(patched_data, patched_data_obj)
                risk_reduction = initial_risk - patched_asset_risk

                # Convert tensors to floats and format to two decimal places
                formatted_patch_effectiveness = (
                    vulnerability.cve_id,
                    round(risk_reduction.item(), 3) if hasattr(risk_reduction, 'item') else round(risk_reduction, 2),
                    round(patched_asset_risk.item(), 3) if hasattr(patched_asset_risk, 'item') else round(patched_asset_risk, 3),
                    vulnerability.cvss,
                    vulnerability.exploit,
                    component.id,
                    vulnerability.likelihood,
                    vulnerability.impact,
                    vulnerability.scopeChanged,
                    vulnerability.ransomWare,
                    vulnerability.epss,
                )

                patch_effectiveness.append(formatted_patch_effectiveness)

        patch_effectiveness.sort(key=lambda x: x[1], reverse=True)   

        # Print the results in the desired format
        for patch in patch_effectiveness:
            vuln_id, risk_reduction, patched_asset_risk, cvss, exploit, component_id, likelihood, impact, scopeChanged, ransomWare, epss = patch
            print(f"{vuln_id} —> patched asset risk is {patched_asset_risk}")
            print(
                f"—> Scope changed is {scopeChanged} and utilized Ransomware is {ransomWare}")
            print(f"—> CVSS is {cvss}, with likelihood as {likelihood} and impact as {impact}")
            print(f"—> EPSS score is {epss}")
            print(f"—> existing exploit is {exploit}")
            print(f"—> exists in Component {component_id}")
            print()

        return patch_effectiveness 

    elif level == 'system':
        # Iterate over all assets and their components
        for asset_idx, asset in enumerate(data.assets):
            for comp_idx, component in enumerate(asset.components):
                for vul_idx, vulnerability in enumerate(component.vulnerabilities):
                    patched_data = simulate_patch_system(data, asset_idx, comp_idx, vul_idx)

                    # Recalculate risks for all assets in the patched data
                    for patched_asset in patched_data.assets:
                        G, data_obj = generate_sub_graph(patched_asset)
                        _, _, _, total_propagated_risk = calculate_asset_risk(patched_asset, data_obj)
                        # Update the patched asset's total propagated risk
                        patched_asset.total_propagated_risk = total_propagated_risk

                    # Calculate the system-level risk for the patched data
                    patched_system_risk = calculate_system_risk(main_graph, patched_data, comp_centrality_data)

                    # Calculate the risk reduction
                    risk_reduction = initial_risk - patched_system_risk

                    # Prepare the formatted result
                    formatted_patch_effectiveness = (
                        vulnerability.cve_id,
                        round(risk_reduction, 3),
                        round(patched_system_risk, 3),
                        vulnerability.cvss,
                        vulnerability.exploit,
                        component.id,
                        asset.name,  # Include asset name
                        vulnerability.likelihood,
                        vulnerability.impact,
                        vulnerability.scopeChanged,
                        vulnerability.ransomWare,
                        vulnerability.epss
                    )

                    patch_effectiveness.append(formatted_patch_effectiveness)

        # Sort patches by the effectiveness of risk reduction
        patch_effectiveness.sort(key=lambda x: x[1], reverse=True)

        # Print the results in the desired format
        for patch in patch_effectiveness:
            vuln_id, risk_reduction, patched_system_risk, cvss, exploit, component_id, asset_name, likelihood, impact, scopeChanged, ransomWare, epss = patch
            print(f"{vuln_id} —> patched system risk is {patched_system_risk}")
            print(f"—> Scope changed is {scopeChanged}")
            print(f"—> CVSS is {cvss}, with likelihood as {likelihood} and impact as {impact}")
            print(f"—> existing exploit is {exploit}")
            print(f"—> exists in Component {component_id} in Asset {asset_name}")
            print()

        return patch_effectiveness
    
def simulate_patch_asset(data, component_idx, vulnerability_idx):
    """
    Input: <Asset>
    """
    patched_data = copy.deepcopy(data)
    if patched_data.components[component_idx].vulnerabilities:
        # Remove the vulnerability from the component
        removed_vulnerability = patched_data.components[component_idx].vulnerabilities.pop(vulnerability_idx)
        # Also remove the vulnerability from the 'Vulnerabilities' list
        patched_data.vulnerabilities = [
            v for v in patched_data.vulnerabilities
            if not (v.cve_id == removed_vulnerability.cve_id and v.component_id == removed_vulnerability.component_id)
        ]
    return patched_data

def simulate_patch_system(data, asset_idx, component_idx, vulnerability_idx):
    patched_data = copy.deepcopy(data)
    # Locate the target asset and component
    asset = patched_data.assets[asset_idx]
    component = asset.components[component_idx]

    # Remove the specific vulnerability
    if component.vulnerabilities and vulnerability_idx < len(component.vulnerabilities):
        removed_vulnerability = component.vulnerabilities.pop(vulnerability_idx)

        # Remove the vulnerability from the global list if applicable
        patched_data.vulnerabilities = [
            v for v in patched_data.assets[0].vulnerabilities
            if not (v.cve_id == removed_vulnerability.cve_id and v.component_id == removed_vulnerability.component_id)
        ]

    return patched_data

def rank_vulnerabilities_by_cvss(data, level='asset'):
    """
    Rank vulnerabilities based on CVSS base scores only.
    
    Parameters:
    - data: A System or Asset-level dataset containing vulnerabilities
    - level: Either 'asset' or 'system', determines how to process the data
    """

    # List to hold vulnerabilities with CVSS score
    vulnerabilities_with_cvss = []

    # Process asset-level vulnerabilities
    if level == 'system':
        for asset in data.assets:
            for component in asset.components:
                for vulnerability in component.vulnerabilities:
                    # Check if vulnerability is a dictionary
                    if isinstance(vulnerability, Vulnerability):
                        if vulnerability.cvss is not None:
                            vulnerabilities_with_cvss.append({
                                'cve_id': vulnerability.cve_id,
                                'cvss': vulnerability.cvss,
                                'asset': asset.name,
                                'component': component.name,
                                'component_id': component.id,
                            })
                    else:
                        # Skip and print a warning if vulnerability format is invalid
                        print(f"Skipping invalid vulnerability format in component: {component.name} (asset: {asset.name})")
        
    elif level == 'asset':
        for component in data.components:
            for vulnerability in component.vulnerabilities:
                # Check if vulnerability is a dictionary
                if isinstance(vulnerability, Vulnerability):
                    if vulnerability.cvss is not None:
                        vulnerabilities_with_cvss.append({
                            'cve_id': vulnerability.cve_id,
                            'cvss': vulnerability.cvss,
                            'component': component.name,
                            'component_id': component.id,
                        })
                else:
                    # Skip and print a warning if vulnerability format is invalid
                    print(f"Skipping invalid vulnerability format in component: {component.name} (asset: {asset.name})")

    # Sort vulnerabilities based on CVSS score (highest to lowest)
    ranked_vulnerabilities = sorted(vulnerabilities_with_cvss, key=lambda x: x['cvss'], reverse=True)

    # Print the ranked vulnerabilities
    print("\nRanked Vulnerabilities by CVSS Score:")
    if level == 'system':
        for idx, vulnerability in enumerate(ranked_vulnerabilities, start=1):
            print(f"{idx}. CVE ID: {vulnerability['cve_id']} | CVSS Score: {vulnerability['cvss']} | Asset: {vulnerability['asset']} | Component: {vulnerability['component']} (ID: {vulnerability['component_id']})")
    elif level == 'asset':
         # Print without the asset name since it is only one asset
         for idx, vulnerability in enumerate(ranked_vulnerabilities, start=1):
            print(f"{idx}. CVE ID: {vulnerability['cve_id']} | CVSS Score: {vulnerability['cvss']} |  Component: {vulnerability['component']} (ID: {vulnerability['component_id']})")
    return ranked_vulnerabilities