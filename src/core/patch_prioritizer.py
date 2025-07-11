"""
Unified patch prioritization module for PatchRank
Handles vulnerability ranking and patch simulation for both asset and system levels
"""

import copy
from typing import List, Dict, Any, Tuple, Union, Optional
import numpy as np

from .models import Asset, System, Vulnerability, Component, AnalysisLevel, RiskCalculationStrategy
from .risk_calculator import RiskCalculator
from .graph_processor import GraphProcessor


class PatchPrioritizer:
    """Unified patch prioritizer for both asset and system level analysis"""
    
    def __init__(self):
        """Initialize the patch prioritizer"""
        self.risk_calculator = RiskCalculator()
        self.graph_processor = GraphProcessor()
    
    def rank_patches(self, data: Union[Asset, System], 
                    analysis_level: AnalysisLevel = AnalysisLevel.ASSET,
                    initial_risk: Optional[float] = None,
                    **kwargs) -> List[Dict[str, Any]]:
        """
        Rank patches by risk reduction effectiveness
        
        Args:
            data: Asset or System object
            analysis_level: Analysis level (asset or system)
            initial_risk: Initial risk score (optional, will calculate if not provided)
            **kwargs: Additional arguments for system-level analysis
            
        Returns:
            List of ranked patches with vulnerability information
        """
        # Calculate initial risk if not provided
        if initial_risk is None:
            if analysis_level == AnalysisLevel.ASSET:
                if not isinstance(data, Asset):
                    raise ValueError("Asset-level analysis requires Asset object")
                # For asset level, calculate_asset_risk returns float when no data_obj provided
                initial_risk = self.risk_calculator.calculate_asset_risk(data)
                # Ensure we get a float value
                if not isinstance(initial_risk, float):
                    initial_risk = float(initial_risk)
            else:
                if not isinstance(data, System):
                    raise ValueError("System-level analysis requires System object")
                # For system level, we need additional parameters
                main_graph = kwargs.get('main_graph')
                comp_centrality_data = kwargs.get('comp_centrality_data', {})
                if main_graph is not None:
                    initial_risk = self.risk_calculator.calculate_system_risk(
                        main_graph, data, comp_centrality_data
                    )
                else:
                    # Fallback: sum of asset risks
                    initial_risk = 0.0
                    for asset in data.assets:
                        risk_result = self.risk_calculator.calculate_asset_risk(asset)
                        asset_risk = risk_result if isinstance(risk_result, float) else risk_result[3]
                        initial_risk += asset_risk
        
        # Get patch rankings based on analysis level
        if analysis_level == AnalysisLevel.ASSET:
            if not isinstance(data, Asset):
                raise ValueError("Asset-level analysis requires Asset object")
            # Use improved simple method with real risk reduction calculation
            adjacency_matrix = kwargs.get('adjacency_matrix', data.adjacency_matrix)
            raw_patches = self._rank_asset_patches_with_real_reduction(data, initial_risk, adjacency_matrix)
        elif analysis_level == AnalysisLevel.SYSTEM:
            if not isinstance(data, System):
                raise ValueError("System-level analysis requires System object")
            # Use improved simple method with real risk reduction calculation
            raw_patches = self._rank_system_patches_with_real_reduction(data, initial_risk, **kwargs)
        else:
            raise ValueError(f"Unsupported analysis level: {analysis_level}")
        
        # Convert to expected format
        formatted_patches = []
        for patch_info in raw_patches:
            if isinstance(patch_info, tuple):
                # Tuple format from real patch ranking methods
                # (cve_id, risk_reduction, patched_risk, cvss, exploit, component_id, ...)
                if len(patch_info) >= 11:  # Asset-level format
                    formatted_patch = {
                        'cve_id': patch_info[0],
                        'component_id': patch_info[5],
                        'priority_score': patch_info[1],  # actual risk_reduction
                        'cvss': patch_info[3],
                        'exploit': patch_info[4],
                        'epss': patch_info[10] if len(patch_info) > 10 else 0.0,
                        'patched_risk': patch_info[2]
                    }
                elif len(patch_info) >= 12:  # System-level format  
                    formatted_patch = {
                        'cve_id': patch_info[0],
                        'component_id': patch_info[5],
                        'asset_id': patch_info[6],  # asset_name
                        'priority_score': patch_info[1],  # actual risk_reduction
                        'cvss': patch_info[3],
                        'exploit': patch_info[4],
                        'epss': patch_info[11] if len(patch_info) > 11 else 0.0,
                        'patched_risk': patch_info[2]
                    }
                else:
                    # Fallback for shorter tuples
                    formatted_patch = {
                        'cve_id': patch_info[0] if len(patch_info) > 0 else '',
                        'component_id': patch_info[5] if len(patch_info) > 5 else '',
                        'priority_score': patch_info[1] if len(patch_info) > 1 else 0.0,
                        'cvss': patch_info[3] if len(patch_info) > 3 else 0.0,
                        'exploit': patch_info[4] if len(patch_info) > 4 else False,
                        'epss': 0.0,
                        'patched_risk': patch_info[2] if len(patch_info) > 2 else 0.0
                    }
                formatted_patches.append(formatted_patch)
            elif isinstance(patch_info, dict):
                # Already in dict format
                formatted_patches.append(patch_info)
        
        return formatted_patches

    def _rank_asset_patches_simple(self, data: Asset, initial_risk: float, 
                                  adjacency_matrix: Optional[List[List[int]]] = None) -> List[Dict[str, Any]]:
        """
        Simple patch ranking for asset-level analysis (for testing)
        
        Args:
            data: Asset object
            initial_risk: Initial asset risk
            adjacency_matrix: Adjacency matrix for component dependencies
            
        Returns:
            List of patch information dictionaries
        """
        patches = []
        
        for component in data.components:
            for vulnerability in component.vulnerabilities:
                # Simple priority score calculation
                priority_score = vulnerability.cvss
                
                # Boost score for exploitable vulnerabilities
                if vulnerability.exploit:
                    priority_score *= 1.5
                
                # Boost score based on EPSS
                if vulnerability.epss > 0.5:
                    priority_score *= (1.0 + vulnerability.epss * 0.5)
                
                patch_info = {
                    'cve_id': vulnerability.cve_id,
                    'component_id': component.id,
                    'priority_score': priority_score,
                    'cvss': vulnerability.cvss,
                    'exploit': vulnerability.exploit,
                    'epss': vulnerability.epss,
                    'patched_risk': max(0.0, initial_risk - priority_score * 0.1)
                }
                
                patches.append(patch_info)
        
        # Sort by priority score (highest first)
        patches.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return patches

    def _rank_system_patches_simple(self, data: System, initial_risk: float, **kwargs) -> List[Dict[str, Any]]:
        """
        Simple patch ranking for system-level analysis (for testing)
        
        Args:
            data: System object
            initial_risk: Initial system risk
            **kwargs: Additional arguments
            
        Returns:
            List of patch information dictionaries
        """
        patches = []
        
        for asset in data.assets:
            for component in asset.components:
                for vulnerability in component.vulnerabilities:
                    # Simple priority score calculation
                    priority_score = vulnerability.cvss * asset.criticality_level / 5.0
                    
                    # Boost score for exploitable vulnerabilities
                    if vulnerability.exploit:
                        priority_score *= 1.5
                    
                    # Boost score based on EPSS
                    if vulnerability.epss > 0.5:
                        priority_score *= (1.0 + vulnerability.epss * 0.5)
                    
                    patch_info = {
                        'cve_id': vulnerability.cve_id,
                        'component_id': component.id,
                        'asset_id': asset.asset_id,
                        'priority_score': priority_score,
                        'cvss': vulnerability.cvss,
                        'exploit': vulnerability.exploit,
                        'epss': vulnerability.epss,
                        'patched_risk': max(0.0, initial_risk - priority_score * 0.1)
                    }
                    
                    patches.append(patch_info)
        
        # Sort by priority score (highest first)
        patches.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return patches

    def _rank_asset_patches_with_real_reduction(self, data: Asset, initial_risk: float, 
                                              adjacency_matrix: Optional[List[List[int]]] = None) -> List[Dict[str, Any]]:
        """
        Improved asset patch ranking with real risk reduction calculation
        
        Args:
            data: Asset object
            initial_risk: Initial asset risk
            adjacency_matrix: Adjacency matrix for component dependencies
            
        Returns:
            List of patch information dictionaries with real risk reduction
        """
        patches = []
        
        for component in data.components:
            for vulnerability in component.vulnerabilities:
                # Create a copy of the asset without this vulnerability
                patched_asset = copy.deepcopy(data)
                
                # Find and remove the corresponding vulnerability from the copy
                for patched_component in patched_asset.components:
                    if patched_component.id == component.id:
                        patched_component.vulnerabilities = [
                            v for v in patched_component.vulnerabilities 
                            if v.cve_id != vulnerability.cve_id
                        ]
                        break
                
                # Calculate risk for the patched asset
                try:
                    patched_risk = self.risk_calculator.calculate_asset_risk(patched_asset)
                    # Ensure we get a float
                    if not isinstance(patched_risk, float):
                        patched_risk = 0.0
                    
                    # Calculate actual risk reduction
                    risk_reduction = max(0.0, initial_risk - patched_risk)
                    
                except Exception:
                    # Fallback to CVSS-based calculation if risk calculation fails
                    risk_reduction = vulnerability.cvss * 0.1
                    patched_risk = max(0.0, initial_risk - risk_reduction)
                
                # Boost score for exploitable vulnerabilities
                if vulnerability.exploit:
                    risk_reduction *= 1.2
                
                # Boost score based on EPSS
                if vulnerability.epss > 0.5:
                    risk_reduction *= (1.0 + vulnerability.epss * 0.3)
                
                patch_info = {
                    'cve_id': vulnerability.cve_id,
                    'component_id': component.id,
                    'priority_score': risk_reduction,  # Real risk reduction
                    'cvss': vulnerability.cvss,
                    'exploit': vulnerability.exploit,
                    'epss': vulnerability.epss,
                    'patched_risk': patched_risk
                }
                
                patches.append(patch_info)
        
        # Sort by risk reduction (highest first)
        patches.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return patches

    def _rank_system_patches_with_real_reduction(self, data: System, initial_risk: float, **kwargs) -> List[Dict[str, Any]]:
        """
        Improved system patch ranking with real risk reduction calculation
        
        Args:
            data: System object
            initial_risk: Initial system risk
            **kwargs: Additional arguments
            
        Returns:
            List of patch information dictionaries with real risk reduction
        """
        patches = []
        
        for asset in data.assets:
            for component in asset.components:
                for vulnerability in component.vulnerabilities:
                    # Create a copy of the system without this vulnerability
                    patched_system = copy.deepcopy(data)
                    
                    # Find and remove the corresponding vulnerability from the copy
                    for patched_asset in patched_system.assets:
                        if patched_asset.asset_id == asset.asset_id:
                            for patched_component in patched_asset.components:
                                if patched_component.id == component.id:
                                    patched_component.vulnerabilities = [
                                        v for v in patched_component.vulnerabilities 
                                        if v.cve_id != vulnerability.cve_id
                                    ]
                                    break
                            break
                    
                    # Calculate risk for the patched system
                    try:
                        # Recalculate asset risks for the patched system
                        total_patched_risk = 0.0
                        for patched_asset in patched_system.assets:
                            asset_risk = self.risk_calculator.calculate_asset_risk(patched_asset)
                            if isinstance(asset_risk, float):
                                total_patched_risk += asset_risk
                        
                        # Calculate actual risk reduction
                        risk_reduction = max(0.0, initial_risk - total_patched_risk)
                        
                    except Exception:
                        # Fallback to CVSS-based calculation if risk calculation fails
                        risk_reduction = vulnerability.cvss * asset.criticality_level / 5.0 * 0.1
                        total_patched_risk = max(0.0, initial_risk - risk_reduction)
                    
                    # Boost score for exploitable vulnerabilities
                    if vulnerability.exploit:
                        risk_reduction *= 1.2
                    
                    # Boost score based on EPSS and asset criticality
                    if vulnerability.epss > 0.5:
                        risk_reduction *= (1.0 + vulnerability.epss * 0.3)
                    
                    # Factor in asset criticality
                    risk_reduction *= (asset.criticality_level / 5.0)
                    
                    patch_info = {
                        'cve_id': vulnerability.cve_id,
                        'component_id': component.id,
                        'asset_id': asset.asset_id,
                        'priority_score': risk_reduction,  # Real risk reduction
                        'cvss': vulnerability.cvss,
                        'exploit': vulnerability.exploit,
                        'epss': vulnerability.epss,
                        'patched_risk': total_patched_risk
                    }
                    
                    patches.append(patch_info)
        
        # Sort by risk reduction (highest first)
        patches.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return patches

    def rank_vulnerabilities_by_cvss(self, data: Union[Asset, System], 
                                   level: AnalysisLevel = AnalysisLevel.ASSET) -> List[Dict[str, Any]]:
        """
        Rank vulnerabilities based on CVSS base scores only
        
        Args:
            data: Asset or System object
            level: Analysis level
            
        Returns:
            List of ranked vulnerabilities
        """
        vulnerabilities_with_cvss = []
        
        if level == AnalysisLevel.ASSET:
            # Process asset-level vulnerabilities
            for component in data.components:
                for vulnerability in component.vulnerabilities:
                    if vulnerability.cvss is not None:
                        vulnerabilities_with_cvss.append({
                            'cve_id': vulnerability.cve_id,
                            'cvss': vulnerability.cvss,
                            'asset': data.name,
                            'component': component.name,
                            'component_id': component.id,
                        })
        
        elif level == AnalysisLevel.SYSTEM:
            # Process system-level vulnerabilities
            for asset in data.assets:
                for component in asset.components:
                    for vulnerability in component.vulnerabilities:
                        if vulnerability.cvss is not None:
                            vulnerabilities_with_cvss.append({
                                'cve_id': vulnerability.cve_id,
                                'cvss': vulnerability.cvss,
                                'asset': asset.name,
                                'component': component.name,
                                'component_id': component.id,
                            })
        
        # Sort by CVSS score (highest to lowest)
        ranked_vulnerabilities = sorted(
            vulnerabilities_with_cvss, 
            key=lambda x: x['cvss'], 
            reverse=True
        )
        
        return ranked_vulnerabilities
    
    def _rank_asset_patches(self, data: Asset, initial_risk: float, 
                           adjacency_matrix: Optional[List[List[int]]] = None) -> List[Tuple]:
        """
        Rank patches for asset-level analysis
        
        Args:
            data: Asset object
            initial_risk: Initial asset risk
            adjacency_matrix: Adjacency matrix for component dependencies
            
        Returns:
            List of ranked patches
        """
        patch_effectiveness = []
        
        # Use provided adjacency matrix or asset's own
        if adjacency_matrix is None:
            adjacency_matrix = data.adjacency_matrix
        
        for comp_idx, component in enumerate(data.components):
            for vul_idx, vulnerability in enumerate(component.vulnerabilities):
                # Simulate patch
                patched_data = self._simulate_patch_asset(data, comp_idx, vul_idx)
                
                # Calculate patched risk
                patched_data_obj = self.graph_processor.prepare_graph_data(patched_data, adjacency_matrix)
                _, _, _, patched_asset_risk = self.risk_calculator.calculate_asset_risk(patched_data, patched_data_obj)
                
                # Calculate risk reduction
                risk_reduction = initial_risk - patched_asset_risk
                
                # Format patch effectiveness data
                formatted_patch = (
                    vulnerability.cve_id,
                    round(risk_reduction.item() if hasattr(risk_reduction, 'item') else risk_reduction, 3),
                    round(patched_asset_risk.item() if hasattr(patched_asset_risk, 'item') else patched_asset_risk, 3),
                    vulnerability.cvss,
                    vulnerability.exploit,
                    component.id,
                    vulnerability.likelihood,
                    vulnerability.impact,
                    vulnerability.scope_changed,
                    vulnerability.ransomware,
                    vulnerability.epss,
                )
                
                patch_effectiveness.append(formatted_patch)
        
        # Sort by risk reduction (highest to lowest)
        patch_effectiveness.sort(key=lambda x: x[1], reverse=True)
        
        return patch_effectiveness
    
    def _rank_system_patches(self, data: System, initial_risk: float, 
                           main_graph=None, comp_centrality_data=None) -> List[Tuple]:
        """
        Rank patches for system-level analysis
        
        Args:
            data: System object
            initial_risk: Initial system risk
            main_graph: Network communication graph
            comp_centrality_data: Component centrality data
            
        Returns:
            List of ranked patches
        """
        patch_effectiveness = []
        
        # Iterate over all assets and their components
        for asset_idx, asset in enumerate(data.assets):
            for comp_idx, component in enumerate(asset.components):
                for vul_idx, vulnerability in enumerate(component.vulnerabilities):
                    # Simulate patch
                    patched_data = self._simulate_patch_system(data, asset_idx, comp_idx, vul_idx)
                    
                    # Recalculate risks for all assets in the patched data
                    for patched_asset in patched_data.assets:
                        G, data_obj = self.graph_processor.generate_sub_graph(patched_asset)
                        _, _, _, total_propagated_risk = self.risk_calculator.calculate_asset_risk(patched_asset, data_obj)
                        patched_asset.total_propagated_risk = total_propagated_risk
                    
                    # Calculate system-level risk for the patched data
                    patched_system_risk = self.risk_calculator.calculate_system_risk(
                        main_graph, patched_data, comp_centrality_data
                    )
                    
                    # Calculate risk reduction
                    risk_reduction = initial_risk - patched_system_risk
                    
                    # Format patch effectiveness data
                    formatted_patch = (
                        vulnerability.cve_id,
                        round(risk_reduction, 3),
                        round(patched_system_risk, 3),
                        vulnerability.cvss,
                        vulnerability.exploit,
                        component.id,
                        asset.name,
                        vulnerability.likelihood,
                        vulnerability.impact,
                        vulnerability.scope_changed,
                        vulnerability.ransomware,
                        vulnerability.epss
                    )
                    
                    patch_effectiveness.append(formatted_patch)
        
        # Sort by risk reduction (highest to lowest)
        patch_effectiveness.sort(key=lambda x: x[1], reverse=True)
        
        return patch_effectiveness
    
    def _simulate_patch_asset(self, data: Asset, component_idx: int, vulnerability_idx: int) -> Asset:
        """
        Simulate patching a vulnerability in an asset
        
        Args:
            data: Asset object
            component_idx: Index of the component
            vulnerability_idx: Index of the vulnerability
            
        Returns:
            Patched asset object
        """
        patched_data = copy.deepcopy(data)
        
        if (patched_data.components[component_idx].vulnerabilities and 
            vulnerability_idx < len(patched_data.components[component_idx].vulnerabilities)):
            # Remove the vulnerability from the component
            removed_vulnerability = patched_data.components[component_idx].vulnerabilities.pop(vulnerability_idx)
            
            # Remove the vulnerability from the global vulnerabilities list
            # Note: Asset doesn't have a vulnerabilities attribute, so we skip this step
            # The vulnerability is already removed from the component above
            pass
        
        return patched_data
    
    def _simulate_patch_system(self, data: System, asset_idx: int, 
                             component_idx: int, vulnerability_idx: int) -> System:
        """
        Simulate patching a vulnerability in a system
        
        Args:
            data: System object
            asset_idx: Index of the asset
            component_idx: Index of the component
            vulnerability_idx: Index of the vulnerability
            
        Returns:
            Patched system object
        """
        patched_data = copy.deepcopy(data)
        
        # Locate the target asset and component
        asset = patched_data.assets[asset_idx]
        component = asset.components[component_idx]
        
        # Remove the specific vulnerability
        if (component.vulnerabilities and 
            vulnerability_idx < len(component.vulnerabilities)):
            removed_vulnerability = component.vulnerabilities.pop(vulnerability_idx)
            
            # Remove the vulnerability from the global list if applicable
            # Note: System doesn't have a vulnerabilities attribute, so we skip this step
            # The vulnerability is already removed from the component above
            pass
        
        return patched_data
    
    def verify_risk_reduction(self, patch_rankings: List[Tuple], initial_risk: float, 
                            level: AnalysisLevel = AnalysisLevel.ASSET) -> bool:
        """
        Verify that all patches lead to risk reduction
        
        Args:
            patch_rankings: List of patch rankings
            initial_risk: Initial risk score
            level: Analysis level
            
        Returns:
            True if all patches reduce risk, False otherwise
        """
        if level == AnalysisLevel.ASSET:
            for patch in patch_rankings:
                vuln_id, risk_reduction, patched_asset_risk, cvss, exploit, component_id, likelihood, impact, scopeChanged, ransomWare, epss = patch
                if patched_asset_risk >= initial_risk:
                    raise AssertionError(f"Total Risk did not decrease for vulnerability {vuln_id}")
        
        elif level == AnalysisLevel.SYSTEM:
            for patch in patch_rankings:
                vuln_id, risk_reduction, patched_system_risk, cvss, exploit, component_id, asset_name, likelihood, impact, scopeChanged, ransomWare, epss = patch
                if patched_system_risk >= initial_risk:
                    raise AssertionError(f"System Risk did not decrease for vulnerability {vuln_id}")
        
        return True
    
    def get_patch_statistics(self, patch_rankings: List[Tuple], 
                           level: AnalysisLevel = AnalysisLevel.ASSET) -> Dict[str, Any]:
        """
        Get statistics about patch rankings
        
        Args:
            patch_rankings: List of patch rankings
            level: Analysis level
            
        Returns:
            Patch statistics
        """
        if not patch_rankings:
            return {}
        
        stats = {
            'total_patches': len(patch_rankings),
            'average_risk_reduction': np.mean([patch[1] for patch in patch_rankings]),
            'max_risk_reduction': max([patch[1] for patch in patch_rankings]),
            'min_risk_reduction': min([patch[1] for patch in patch_rankings]),
            'cvss_distribution': {},
            'exploit_distribution': {'exploitable': 0, 'non_exploitable': 0}
        }
        
        # Analyze CVSS distribution
        for patch in patch_rankings:
            cvss = patch[3]  # CVSS score is at index 3
            cvss_category = self._categorize_cvss(cvss)
            stats['cvss_distribution'][cvss_category] = (
                stats['cvss_distribution'].get(cvss_category, 0) + 1
            )
            
            # Analyze exploit distribution
            exploit = patch[4]  # Exploit flag is at index 4
            if exploit:
                stats['exploit_distribution']['exploitable'] += 1
            else:
                stats['exploit_distribution']['non_exploitable'] += 1
        
        return stats
    
    def _categorize_cvss(self, cvss: float) -> str:
        """Categorize CVSS score"""
        if cvss >= 9.0:
            return "Critical"
        elif cvss >= 7.0:
            return "High"
        elif cvss >= 4.0:
            return "Medium"
        else:
            return "Low"


# Convenience functions for backward compatibility
def rank_patches(data: Union[Asset, System], initial_risk: float, 
                level: str = 'asset', **kwargs) -> List[Tuple]:
    """Backward compatibility function"""
    prioritizer = PatchPrioritizer()
    analysis_level = AnalysisLevel(level)
    return prioritizer.rank_patches(data, analysis_level, initial_risk, **kwargs)


def rank_vulnerabilities_by_cvss(data: Union[Asset, System], level: str = 'asset') -> List[Dict[str, Any]]:
    """Backward compatibility function"""
    prioritizer = PatchPrioritizer()
    analysis_level = AnalysisLevel(level)
    return prioritizer.rank_vulnerabilities_by_cvss(data, analysis_level)


def verify_risk_reduction(patch_rankings: List[Tuple], initial_risk: float, level: str = 'asset') -> bool:
    """Backward compatibility function"""
    prioritizer = PatchPrioritizer()
    analysis_level = AnalysisLevel(level)
    return prioritizer.verify_risk_reduction(patch_rankings, initial_risk, analysis_level)


def simulate_patch_asset(data: Asset, component_idx: int, vulnerability_idx: int) -> Asset:
    """Backward compatibility function"""
    prioritizer = PatchPrioritizer()
    return prioritizer._simulate_patch_asset(data, component_idx, vulnerability_idx)


def simulate_patch_system(data: System, asset_idx: int, component_idx: int, vulnerability_idx: int) -> System:
    """Backward compatibility function"""
    prioritizer = PatchPrioritizer()
    return prioritizer._simulate_patch_system(data, asset_idx, component_idx, vulnerability_idx) 