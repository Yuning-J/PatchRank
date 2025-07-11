"""
Improved main module for PatchRank using unified architecture
Maintains backward compatibility while using the new core modules
"""

import argparse
import os
import time
import sys
from typing import Union

# Add the current directory to the path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import conf
from core import (
    DataLoader, RiskCalculator, GraphProcessor, DependencyCalculator, PatchPrioritizer,
    Asset, System, AnalysisLevel, RiskCalculationStrategy
)


class PatchRankAnalyzer:
    """Unified analyzer for PatchRank using improved architecture"""
    
    def __init__(self, data_path: str = None):
        """
        Initialize the analyzer
        
        Args:
            data_path: Path to data directory (optional)
        """
        if data_path is None:
            # Fix the path to work from the project root
            import os
            project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            data_path = os.path.join(project_root, 'data', 'asset_withVul_data')
        
        self.data_loader = DataLoader(data_path)
        self.risk_calculator = RiskCalculator()
        self.graph_processor = GraphProcessor()
        # Fix the asset data path to work from the project root
        asset_data_path = os.path.join(project_root, 'data', 'asset_data')
        self.dependency_calculator = DependencyCalculator(asset_data_path)
        self.patch_prioritizer = PatchPrioritizer()
    
    def analyze(self, level: str, data_file: str, cvss_only: bool = False) -> dict:
        """
        Perform vulnerability analysis
        
        Args:
            level: Analysis level ('asset' or 'system')
            data_file: Name of the data file
            cvss_only: Whether to use CVSS-only ranking
            
        Returns:
            Analysis results
        """
        start_time = time.time()
        
        # Load data
        data = self.data_loader.load_data(data_file)
        
        if cvss_only:
            return self._analyze_cvss_only(data, level)
        
        if level == 'asset':
            return self._analyze_asset_level(data)
        elif level == 'system':
            return self._analyze_system_level(data, data_file)
        else:
            raise ValueError(f"Unsupported analysis level: {level}")
    
    def _analyze_cvss_only(self, data: Union[Asset, System], level: str) -> dict:
        """Perform CVSS-only analysis"""
        analysis_level = AnalysisLevel(level)
        ranked_vulnerabilities = self.patch_prioritizer.rank_vulnerabilities_by_cvss(data, analysis_level)
        
        print("\nRanked Vulnerabilities by CVSS Score:")
        for idx, vulnerability in enumerate(ranked_vulnerabilities, start=1):
            print(f"{idx}. CVE ID: {vulnerability['cve_id']} | "
                  f"CVSS Score: {vulnerability['cvss']} | "
                  f"Asset: {vulnerability['asset']} | "
                  f"Component: {vulnerability['component']} (ID: {vulnerability['component_id']})")
        
        return {
            'analysis_type': 'cvss_only',
            'level': level,
            'ranked_vulnerabilities': ranked_vulnerabilities
        }
    
    def _analyze_asset_level(self, data: Asset) -> dict:
        """Perform asset-level analysis"""
        print(f"Performing asset-level analysis for: {data.name}")
        
        # Prepare graph data
        adjacency_matrix = data.adjacency_matrix
        data_obj = self.graph_processor.prepare_graph_data(data, adjacency_matrix)
        
        # Calculate initial risks
        initial_cvs, initial_centrality, initial_component_risks, initial_asset_risk = (
            self.risk_calculator.calculate_asset_risk(data, data_obj)
        )
        
        print(f'Initial Asset Risk: {initial_asset_risk:.4f}')
        print(f'Initial Component Risks: {initial_component_risks}')
        
        # Rank patches
        patch_rankings = self.patch_prioritizer.rank_patches(
            data, initial_asset_risk, AnalysisLevel.ASSET, 
            adjacency_matrix=adjacency_matrix
        )
        
        # Print results
        self._print_asset_patch_results(patch_rankings)
        
        # Generate visualizations
        self._generate_asset_visualizations(data, data_obj, adjacency_matrix, initial_component_risks)
        
        return {
            'analysis_type': 'asset_level',
            'initial_asset_risk': initial_asset_risk,
            'initial_component_risks': initial_component_risks,
            'patch_rankings': patch_rankings,
            'component_risks': initial_component_risks,
            'centrality': initial_centrality
        }
    
    def _analyze_system_level(self, data: System, data_file: str) -> dict:
        """Perform system-level analysis"""
        print(f"Performing system-level analysis for: {data_file}")
        
        # Extract scenario ID from filename
        scenario_id = data_file.split('_')[1].split('.')[0]
        
        # Generate dependency analysis
        centrality_dict = self.dependency_calculator.generate_dependence(data, scenario_id)
        sys_comp_centrality = centrality_dict['component_centrality']
        asset_centrality_provided = centrality_dict['asset_centrality']
        
        # Process each asset
        asset_sub_graphs = {}
        asset_centrality = {}
        
        # Assign provided centrality values
        for asset in data.assets:
            asset_id = asset.asset_id
            asset_centrality[asset_id] = asset_centrality_provided.get(asset_id, 0)
        
        # Calculate risks for each asset
        for asset in data.assets:
            G, data_obj = self.graph_processor.generate_sub_graph(asset)
            _, asset_comp_centrality, _, total_propagated_risk = (
                self.risk_calculator.calculate_asset_risk(asset, data_obj)
            )
            asset.total_propagated_risk = total_propagated_risk
            
            asset_sub_graphs[asset.name] = {
                'graph': G,
                'data_obj': data_obj,
                'total_propagated_risk': total_propagated_risk
            }
        
        # Recalculate asset criticality
        updated_criticality, final_criticality = (
            self.risk_calculator.recalculate_asset_criticality(data.assets, asset_centrality)
        )
        
        # Update criticality levels
        for asset in data.assets:
            asset_id = asset.asset_id
            asset.updated_criticality = updated_criticality[asset_id]
            asset.final_criticality = final_criticality[asset_id]
        
        # Print updated asset information
        for asset in data.assets:
            print(f"Asset: {asset.name}, Total Risk: {asset.total_propagated_risk}, "
                  f"Centrality: {asset_centrality[asset.asset_id]}, "
                  f"Criticality: {asset.updated_criticality}, "
                  f"Integer Criticality: {asset.final_criticality}")
        
        # Generate network graph
        main_graph = self.graph_processor.generate_network_graph(data)
        print("Main Network Graph Connections:")
        for edge in main_graph.edges:
            print(f"{edge[0]} -> {edge[1]}")
        
        # Calculate system-level risk
        initial_system_risk = self.risk_calculator.calculate_system_risk(
            main_graph, data, sys_comp_centrality
        )
        print(f"Initial System-level Risk Score: {initial_system_risk}")
        
        # Rank patches
        patch_rankings = self.patch_prioritizer.rank_patches(
            data, initial_system_risk, AnalysisLevel.SYSTEM,
            main_graph=main_graph, comp_centrality_data=sys_comp_centrality
        )
        
        # Print results
        self._print_system_patch_results(patch_rankings)
        
        return {
            'analysis_type': 'system_level',
            'initial_system_risk': initial_system_risk,
            'patch_rankings': patch_rankings,
            'asset_centrality': asset_centrality,
            'component_centrality': sys_comp_centrality,
            'main_graph': main_graph
        }
    
    def _print_asset_patch_results(self, patch_rankings: list):
        """Print asset-level patch results"""
        for patch in patch_rankings:
            vuln_id, risk_reduction, patched_asset_risk, cvss, exploit, component_id, likelihood, impact, scopeChanged, ransomWare, epss = patch
            print(f"{vuln_id} —> patched asset risk is {patched_asset_risk}")
            print(f"—> Scope changed is {scopeChanged} and utilized Ransomware is {ransomWare}")
            print(f"—> CVSS is {cvss}, with likelihood as {likelihood} and impact as {impact}")
            print(f"—> EPSS score is {epss}")
            print(f"—> existing exploit is {exploit}")
            print(f"—> exists in Component {component_id}")
            print()
    
    def _print_system_patch_results(self, patch_rankings: list):
        """Print system-level patch results"""
        print('Patch Rankings (Vulnerability ID, Risk Reduction, Patched Asset Risk, CVSS, Exploit, Component, Asset, Likelihood, Impact, ScopeChanged):')
        for patch in patch_rankings:
            vuln_id, risk_reduction, patched_system_risk, cvss, exploit, component_id, asset_name, likelihood, impact, scopeChanged, ransomWare, epss = patch
            print(f"{vuln_id} —> patched system risk is {patched_system_risk}")
            print(f"—> Scope changed is {scopeChanged}")
            print(f"—> CVSS is {cvss}, with likelihood as {likelihood} and impact as {impact}")
            print(f"—> existing exploit is {exploit}")
            print(f"—> exists in Component {component_id} in Asset {asset_name}")
            print()
    
    def _generate_asset_visualizations(self, data: Asset, data_obj, adjacency_matrix: list, component_risks: list):
        """Generate visualizations for asset-level analysis"""
        try:
            from graph_visualization import visualize_results_asset
            visualize_results_asset(data, data_obj, adjacency_matrix, component_risks)
        except ImportError:
            print("Visualization module not available, skipping visualizations")


def main():
    """Main entry point for the improved PatchRank analyzer"""
    parser = argparse.ArgumentParser(description="Asset/System-Level Vulnerability Ranking")
    parser.add_argument(
        "--level",
        choices=["asset", "system"],
        default="asset",
        help="Choose the analysis level: 'asset' or 'system'",
    )
    parser.add_argument(
        "--data",
        required=True,
        help="Filename of the data to be processed",
    )
    parser.add_argument(
        "--cvss_only",
        action="store_true",
        help="Rank vulnerabilities based on CVSS base scores only",
    )
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = PatchRankAnalyzer()
    
    # Perform analysis
    try:
        results = analyzer.analyze(args.level, args.data, args.cvss_only)
        print(f"Analysis completed successfully!")
        return results
    except Exception as e:
        print(f"Error during analysis: {e}")
        raise


if __name__ == "__main__":
    main() 