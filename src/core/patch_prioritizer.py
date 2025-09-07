"""
Patch Prioritization Module

This module provides separate classes for different patch prioritization approaches:
- AssetPatchPrioritizer: Asset-level patch ranking
- SystemPatchPrioritizerShortest: System-level using simple shortest path
- SystemPatchPrioritizerKShortest: System-level using k-shortest paths

Each class uses its own risk calculator for consistent behavior.
"""

import logging
import copy
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

from .models import Asset, System, Component, Vulnerability, AnalysisLevel
from .risk_calculator_system import SystemRiskCalculator
# from .risk_calculator_k_shortest_path import RiskCalculatorKShortestPath  # Removed
from .exploit_score import ExploitScoreCalculator

logger = logging.getLogger(__name__)

@dataclass
class PatchInfo:
    """Information about a patch"""
    vulnerability_id: str
    asset_id: str
    component_id: str
    risk_reduction: float
    cvss_score: float
    epss_score: float
    exploit_score: float
    patch_priority: int
    description: str

class AssetPatchPrioritizer:
    """
    Asset-level patch prioritization
    
    Uses simple shortest path risk calculator for consistent behavior.
    """
    
    def __init__(self, exploit_score_calc: ExploitScoreCalculator = None):
        """Initialize the asset patch prioritizer"""
        if exploit_score_calc is None:
            exploit_score_calc = ExploitScoreCalculator()
        
        self.exploit_score_calc = exploit_score_calc
        # Use base risk calculator for asset-level analysis
        from .risk_calculator import RiskCalculator
        self.risk_calculator = RiskCalculator()
    
    def rank_patches(self, data: Asset, analysis_level: AnalysisLevel = AnalysisLevel.ASSET,
                    initial_risk: float = None, main_graph=None, comp_centrality_data: Dict[str, float] = None) -> List[Dict[str, Any]]:
        """
        Rank patches at asset level
        
        Args:
            data: Asset data (single asset)
            analysis_level: Analysis level (should be AnalysisLevel.ASSET)
            initial_risk: Initial risk score (will calculate if not provided)
            main_graph: Not used for asset-level analysis
            comp_centrality_data: Not used for asset-level analysis
            
        Returns:
            List of ranked patches with risk reduction information
        """
        
        # Validate analysis level
        if analysis_level != AnalysisLevel.ASSET:
            raise ValueError(f"AssetPatchPrioritizer only supports asset-level analysis, got: {analysis_level}")
        logger.info(f"Ranking patches at asset level")
        
        ranked_patches = []
        
        # For asset-level analysis, we work with a single asset
        asset = data
        for component in asset.components:
            for vulnerability in component.vulnerabilities:
                # Create a patch simulation (like the old way)
                patch = {
                    'vulnerability_id': vulnerability.cve_id,
                    'asset_id': asset.asset_id,
                    'component_id': component.id,
                    'description': f'Patch for {vulnerability.cve_id}'
                }
                
                try:
                    # Calculate risk reduction
                    risk_reduction = self._calculate_asset_risk_reduction(asset, vulnerability, patch)
                    
                    # Calculate exploit score
                    exploit_score = self._calculate_exploit_score(vulnerability, asset)
                    
                    # Create patch info
                    patch_info = PatchInfo(
                        vulnerability_id=patch['vulnerability_id'],
                        asset_id=patch['asset_id'],
                        component_id=patch['component_id'],
                        risk_reduction=risk_reduction,
                        cvss_score=vulnerability.cvss,
                        epss_score=vulnerability.epss,
                        exploit_score=exploit_score,
                        patch_priority=0,  # Will be set after ranking
                        description=patch['description']
                    )
                    
                    ranked_patches.append(patch_info)
                    
                except Exception as e:
                    logger.error(f"Error processing patch {patch['vulnerability_id']}: {e}")
                    continue
        
        # Sort by risk reduction (descending)
        ranked_patches.sort(key=lambda x: x.risk_reduction, reverse=True)
        
        # Assign priority ranks
        for i, patch_info in enumerate(ranked_patches):
            patch_info.patch_priority = i + 1
        
        # Format results
        formatted_patches = []
        for patch_info in ranked_patches:
            formatted_patch = {
                'rank': patch_info.patch_priority,
                'vulnerability_id': patch_info.vulnerability_id,
                'asset_id': patch_info.asset_id,
                'component_id': patch_info.component_id,
                'risk_reduction': f"{patch_info.risk_reduction:.4f}",
                'cvss_score': f"{patch_info.cvss_score:.1f}",
                'epss_score': f"{patch_info.epss_score:.3f}",
                'exploit_score': f"{patch_info.exploit_score:.6f}",
                'description': patch_info.description
            }
            formatted_patches.append(formatted_patch)
        
        return formatted_patches

    def _calculate_asset_risk_reduction(self, asset: Asset, vulnerability: Vulnerability, patch: Dict[str, Any]) -> float:
        """
        Calculate risk reduction for an asset-level patch using our current system
        
        Args:
            asset: Asset to patch
            vulnerability: Vulnerability to patch
            patch: Patch information dictionary
            
        Returns:
            Risk reduction value
        """
        try:
            # Calculate initial asset risk using our current system
            initial_risk = self.risk_calculator.calculate_asset_risk(asset)
            
            # Simulate patched asset
            patched_asset = self._simulate_patch_asset(asset, vulnerability, patch)
            
            # Calculate patched asset risk using our current system
            patched_risk = self.risk_calculator.calculate_asset_risk(patched_asset)
            
            # Risk reduction = initial - patched
            risk_reduction = initial_risk - patched_risk
            
            return max(0.0, risk_reduction)  # Ensure non-negative
            
        except Exception as e:
            logger.warning(f"Could not calculate risk reduction for {patch['vulnerability_id']}: {e}")
            # Fallback to simple calculation
            return 0.0
    
    def _calculate_asset_risk(self, asset: Asset) -> float:
        """
        Calculate total risk for an asset
        
        Args:
            asset: Asset to analyze
            
        Returns:
            Total asset risk
        """
        total_risk = 0.0
        
        for component in asset.components:
            for vulnerability in component.vulnerabilities:
                # Calculate exploit likelihood
                exploit_likelihood = self.risk_calculator.calculate_exploit_likelihood(vulnerability, asset.__dict__)
                
                # Calculate direct risk
                impact = vulnerability.impact if hasattr(vulnerability, 'impact') else 0.5
                centrality = self.risk_calculator.calculate_asset_centrality_risk(asset)
                direct_risk = self.risk_calculator.calculate_direct_risk(exploit_likelihood, impact, centrality)
                
                # Calculate propagation likelihood
                propagation_likelihood = self.risk_calculator.calculate_propagation_likelihood(vulnerability)
                
                # Calculate total risk for this vulnerability
                vuln_risk = direct_risk * (1 + propagation_likelihood)
                total_risk += vuln_risk
        
        return total_risk
    
    def _simulate_patch_asset(self, asset: Asset, vulnerability: Vulnerability, patch: Dict[str, Any]) -> Asset:
        """
        Simulate applying a patch to an asset
        
        Args:
            asset: Original asset
            vulnerability: Vulnerability to patch
            patch: Patch information dictionary
            
        Returns:
            Patched asset copy
        """
        # Create a deep copy to avoid modifying the original
        patched_asset = copy.deepcopy(asset)
        
        # Find and remove the vulnerability
        for component in patched_asset.components:
            if component.id == patch['component_id']:
                component.vulnerabilities = [v for v in component.vulnerabilities if v.cve_id != patch['vulnerability_id']]
                break
        
        return patched_asset
    
    def _calculate_exploit_score(self, vulnerability: Vulnerability, asset: Asset) -> float:
        """
        Calculate exploit score for a vulnerability using our current system
        
        Args:
            vulnerability: Vulnerability to analyze
            asset: Asset context
            
        Returns:
            Exploit score
        """
        try:
            # Use our current system for exploit likelihood calculation
            exploit_score = self.risk_calculator.calculate_exploit_likelihood(vulnerability)
            return exploit_score
        except Exception as e:
            logger.warning(f"Could not calculate exploit score for {vulnerability.cve_id}: {e}")
            # Fallback to EPSS or CVSS
            if hasattr(vulnerability, 'epss') and vulnerability.epss > 0:
                return float(vulnerability.epss)
            return float(vulnerability.cvss) / 10.0  # Normalize CVSS to 0-1

class SystemPatchPrioritizerShortest:
    """
    System-level patch prioritization using simple shortest path approach
    
    Uses SystemRiskCalculator with k=1 for consistent behavior.
    """
    
    def __init__(self, exploit_score_calc: ExploitScoreCalculator = None, risk_calculator: SystemRiskCalculator = None):
        """Initialize the system patch prioritizer (shortest path)"""
        if exploit_score_calc is None:
            exploit_score_calc = ExploitScoreCalculator()
        
        self.exploit_score_calc = exploit_score_calc
        self.risk_calculator = risk_calculator if risk_calculator is not None else SystemRiskCalculator(k_paths=1)
    
    def rank_patches(self, data: System, analysis_level: AnalysisLevel = AnalysisLevel.SYSTEM,
                    initial_risk: float = None, main_graph=None, comp_centrality_data: Dict[str, float] = None) -> List[Dict[str, Any]]:
        """
        Rank patches at system level using simple shortest path approach
        
        Args:
            data: System data
            analysis_level: Analysis level (should be AnalysisLevel.SYSTEM)
            initial_risk: Initial system risk (will calculate if not provided)
            main_graph: System network graph
            comp_centrality_data: Component centrality data
            
        Returns:
            List of ranked patches with risk reduction information
        """
        
        # Validate analysis level
        if analysis_level != AnalysisLevel.SYSTEM:
            raise ValueError(f"SystemPatchPrioritizerShortest only supports system-level analysis, got: {analysis_level}")
        
        # Calculate initial system risk if not provided
        if initial_risk is None:
            initial_risk = self.risk_calculator.calculate_system_risk(
                main_graph, data, comp_centrality_data
            )
        
        logger.info(f"Initial system risk: {initial_risk:.6f}")
        
        ranked_patches = []
        
        # Iterate through all assets and their vulnerabilities (like the old way)
        for asset in data.assets:
            for component in asset.components:
                for vulnerability in component.vulnerabilities:
                    # Create a patch simulation (like the old way)
                    patch = {
                        'vulnerability_id': vulnerability.cve_id,
                        'asset_id': asset.asset_id,
                        'component_id': component.id,
                        'description': f'Patch for {vulnerability.cve_id}'
                    }
                    
                    try:
                        # Calculate exploit score BEFORE patching (using original system)
                        exploit_score = self._calculate_exploit_score(patch, data)
                        # print(f"DEBUG PATCH: {patch['vulnerability_id']} - exploit_score={exploit_score:.6f}")  # Commented out to avoid broken pipe
                        
                        # Debug: Try direct calculation
                        vuln_obj = self._find_vulnerability(data, patch)
                        if vuln_obj:
                            asset_obj = next((a for a in data.assets if a.asset_id == patch['asset_id']), None)
                            if asset_obj:
                                direct_calc = self.exploit_score_calc.calculate_exploit_score(vuln_obj, asset_obj.__dict__)
                                # print(f"DEBUG DIRECT: {patch['vulnerability_id']} - direct_calc={direct_calc:.6f}")  # Commented out to avoid broken pipe
                        
                        # Simulate patched system
                        patched_system = self._simulate_patch_system(data, patch)
                        
                        # Recalculate asset risks after patching (like old system)
                        self.risk_calculator.prepare_assets_for_system_calculation(patched_system, None, main_graph)
                        
                        # Calculate patched system risk
                        patched_risk = self.risk_calculator.calculate_system_risk(
                            main_graph, patched_system, comp_centrality_data
                        )
                        
                        # Calculate risk reduction
                        risk_reduction = initial_risk - patched_risk
                        
                        # Create patch info
                        patch_info = PatchInfo(
                            vulnerability_id=patch['vulnerability_id'],
                            asset_id=patch['asset_id'],
                            component_id=patch['component_id'],
                            risk_reduction=max(0.0, risk_reduction),
                            cvss_score=0.0,  # Will be filled from vulnerability
                            epss_score=0.0,  # Will be filled from vulnerability
                            exploit_score=exploit_score,
                            patch_priority=0,  # Will be set after ranking
                            description=patch['description']
                        )
                        
                        # Fill CVSS and EPSS scores
                        vulnerability = self._find_vulnerability(data, patch)
                        if vulnerability:
                            patch_info.cvss_score = vulnerability.cvss
                            patch_info.epss_score = vulnerability.epss
                        
                        ranked_patches.append(patch_info)
                        
                        logger.debug(f"Patch {patch['vulnerability_id']}: risk_reduction={risk_reduction:.6f}, "
                                   f"initial={initial_risk:.6f}, patched={patched_risk:.6f}")
                        
                    except Exception as e:
                        logger.error(f"Error processing patch {patch['vulnerability_id']}: {e}")
                        continue
        
        # Sort by risk reduction (descending)
        ranked_patches.sort(key=lambda x: x.risk_reduction, reverse=True)
        
        # Assign priority ranks
        for i, patch_info in enumerate(ranked_patches):
            patch_info.patch_priority = i + 1
        
        # Format results
        formatted_patches = []
        for patch_info in ranked_patches:
            formatted_patch = {
                'rank': patch_info.patch_priority,
                'vulnerability_id': patch_info.vulnerability_id,
                'asset_id': patch_info.asset_id,
                'component_id': patch_info.component_id,
                'risk_reduction': f"{patch_info.risk_reduction:.4f}",
                'cvss_score': f"{patch_info.cvss_score:.1f}",
                'epss_score': f"{patch_info.epss_score:.3f}",
                'exploit_score': f"{patch_info.exploit_score:.6f}",
                'description': patch_info.description
            }
            formatted_patches.append(formatted_patch)
        
        return formatted_patches
    
    def _simulate_patch_system(self, data: System, patch: Dict[str, Any]) -> System:
        """
        Simulate applying a patch to the system
        
        Args:
            data: Original system
            patch: Patch information dictionary
            
        Returns:
            Patched system copy
        """
        # Create a deep copy to avoid modifying the original
        patched_system = copy.deepcopy(data)
        
        # Find and remove the vulnerability
        for asset in patched_system.assets:
            if asset.asset_id == patch['asset_id']:
                for component in asset.components:
                    if component.id == patch['component_id']:
                        component.vulnerabilities = [v for v in component.vulnerabilities if v.cve_id != patch['vulnerability_id']]
                        break
                        break
                
        return patched_system
    
    def _find_vulnerability(self, data: System, patch: Dict[str, Any]) -> Optional[Vulnerability]:
        """
        Find vulnerability in the system
        
        Args:
            data: System data
            patch: Patch information dictionary
            
        Returns:
            Vulnerability object if found, None otherwise
        """
        for asset in data.assets:
            if asset.asset_id == patch['asset_id']:
                for component in asset.components:
                    if component.id == patch['component_id']:
                        for vulnerability in component.vulnerabilities:
                            if vulnerability.cve_id == patch['vulnerability_id']:
                                return vulnerability
        return None
    
    def _calculate_exploit_score(self, patch: Dict[str, Any], data: System) -> float:
        """
        Calculate exploit score for a patch
        
        Args:
            patch: Patch information dictionary
            data: System data
            
        Returns:
            Exploit score
        """
        vulnerability = self._find_vulnerability(data, patch)
        if not vulnerability:
            return 0.0
        
        try:
            # Find the asset for context
            asset = next((a for a in data.assets if a.asset_id == patch['asset_id']), None)
            asset_dict = asset.__dict__ if asset else {}
            
            # Use same format as risk calculator
            vuln_dict = {
                'exploit': getattr(vulnerability, 'exploit', False),
                'epss_score': getattr(vulnerability, 'epss', 0.0),
                'cvssV3Vector': getattr(vulnerability, 'cvssV3Vector', '')
            }
            return self.exploit_score_calc.calculate_exploit_score(vulnerability.cve_id, asset_dict, vuln_dict)
        except Exception as e:
            logger.warning(f"Could not calculate exploit score for {patch['vulnerability_id']}: {e}")
            return float(vulnerability.exploit)  # Fallback to direct value

class SystemPatchPrioritizerKShortest:
    """
    System-level patch prioritization using k-shortest path approach (Algorithm 2)
    
    Uses SystemRiskCalculator with k>1 for consistent behavior.
    """
    
    def __init__(self, exploit_score_calc: ExploitScoreCalculator = None, k_paths: int = 3, risk_calculator: SystemRiskCalculator = None):
        """Initialize the system patch prioritizer (k-shortest path)"""
        if exploit_score_calc is None:
            exploit_score_calc = ExploitScoreCalculator()
        
        self.exploit_score_calc = exploit_score_calc
        self.risk_calculator = risk_calculator if risk_calculator is not None else SystemRiskCalculator(k_paths=k_paths)
        self.k_paths = k_paths
    
    def rank_patches(self, data: System, analysis_level: AnalysisLevel = AnalysisLevel.SYSTEM,
                    initial_risk: float = None, main_graph=None, comp_centrality_data: Dict[str, float] = None) -> List[Dict[str, Any]]:
        """
        Rank patches at system level using k-shortest path approach
        
        Args:
            data: System data
            analysis_level: Analysis level (should be AnalysisLevel.SYSTEM)
            initial_risk: Initial system risk (will calculate if not provided)
            main_graph: System network graph
            comp_centrality_data: Component centrality data
            
        Returns:
            List of ranked patches with risk reduction information
        """
        
        # Validate analysis level
        if analysis_level != AnalysisLevel.SYSTEM:
            raise ValueError(f"SystemPatchPrioritizerKShortest only supports system-level analysis, got: {analysis_level}")
        
        # Calculate initial system risk if not provided
        if initial_risk is None:
            initial_risk = self.risk_calculator.calculate_system_risk(
                main_graph, data, comp_centrality_data, k_paths=self.k_paths
            )
        
        logger.info(f"Initial system risk: {initial_risk:.6f}")
        
        ranked_patches = []
        
        # Iterate through all assets and their vulnerabilities (like the old way)
        for asset in data.assets:
            for component in asset.components:
                for vulnerability in component.vulnerabilities:
                    # Create a patch simulation (like the old way)
                    patch = {
                        'vulnerability_id': vulnerability.cve_id,
                        'asset_id': asset.asset_id,
                        'component_id': component.id,
                        'description': f'Patch for {vulnerability.cve_id}'
                    }
                    
                    try:
                        # Simulate patched system
                        patched_system = self._simulate_patch_system(data, patch)
                        
                        # Recalculate asset risks after patching (like old system)
                        self.risk_calculator.prepare_assets_for_system_calculation(patched_system, None, main_graph)
                        
                        # Calculate patched system risk
                        patched_risk = self.risk_calculator.calculate_system_risk(
                            main_graph, patched_system, comp_centrality_data, k_paths=self.k_paths
                        )
                        
                        # Calculate risk reduction
                        risk_reduction = initial_risk - patched_risk
                        
                        # Calculate exploit score
                        exploit_score = self._calculate_exploit_score(patch, data)
                        
                        # Create patch info
                        patch_info = PatchInfo(
                            vulnerability_id=patch['vulnerability_id'],
                            asset_id=patch['asset_id'],
                            component_id=patch['component_id'],
                            risk_reduction=max(0.0, risk_reduction),
                            cvss_score=0.0,  # Will be filled from vulnerability
                            epss_score=0.0,  # Will be filled from vulnerability
                            exploit_score=exploit_score,
                            patch_priority=0,  # Will be set after ranking
                            description=patch['description']
                        )
                        
                        # Fill CVSS and EPSS scores
                        vulnerability = self._find_vulnerability(data, patch)
                        if vulnerability:
                            patch_info.cvss_score = vulnerability.cvss
                            patch_info.epss_score = vulnerability.epss
                        
                        ranked_patches.append(patch_info)
                        
                        logger.debug(f"Patch {patch['vulnerability_id']}: risk_reduction={risk_reduction:.6f}, "
                                   f"initial={initial_risk:.6f}, patched={patched_risk:.6f}")
                        
                    except Exception as e:
                        logger.error(f"Error processing patch {patch['vulnerability_id']}: {e}")
                        continue
        
        # Sort by risk reduction (descending)
        ranked_patches.sort(key=lambda x: x.risk_reduction, reverse=True)
        
        # Assign priority ranks
        for i, patch_info in enumerate(ranked_patches):
            patch_info.patch_priority = i + 1
        
        # Format results
        formatted_patches = []
        for patch_info in ranked_patches:
            formatted_patch = {
                'rank': patch_info.patch_priority,
                'vulnerability_id': patch_info.vulnerability_id,
                'asset_id': patch_info.asset_id,
                'component_id': patch_info.component_id,
                'risk_reduction': f"{patch_info.risk_reduction:.4f}",
                'cvss_score': f"{patch_info.cvss_score:.1f}",
                'epss_score': f"{patch_info.epss_score:.3f}",
                'exploit_score': f"{patch_info.exploit_score:.6f}",
                'description': patch_info.description
            }
            formatted_patches.append(formatted_patch)
        
        return formatted_patches
    
    def _simulate_patch_system(self, data: System, patch: Dict[str, Any]) -> System:
        """
        Simulate applying a patch to the system
        
        Args:
            data: Original system
            patch: Patch information dictionary
            
        Returns:
            Patched system copy
        """
        # Create a deep copy to avoid modifying the original
        patched_system = copy.deepcopy(data)
        
        # Find and remove the vulnerability
        for asset in patched_system.assets:
            if asset.asset_id == patch['asset_id']:
                for component in asset.components:
                    if component.id == patch['component_id']:
                        component.vulnerabilities = [v for v in component.vulnerabilities if v.cve_id != patch['vulnerability_id']]
                        break
                break
        
        return patched_system
    
    def _find_vulnerability(self, data: System, patch: Dict[str, Any]) -> Optional[Vulnerability]:
        """
        Find vulnerability in the system
        
        Args:
            data: System data
            patch: Patch information dictionary
            
        Returns:
            Vulnerability object if found, None otherwise
        """
        for asset in data.assets:
            if asset.asset_id == patch['asset_id']:
                for component in asset.components:
                    if component.id == patch['component_id']:
                        for vulnerability in component.vulnerabilities:
                            if vulnerability.cve_id == patch['vulnerability_id']:
                                return vulnerability
        return None
    
    def _calculate_exploit_score(self, patch: Dict[str, Any], data: System) -> float:
        """
        Calculate exploit score for a patch
        
        Args:
            patch: Patch information dictionary
            data: System data
            
        Returns:
            Exploit score
        """
        vulnerability = self._find_vulnerability(data, patch)
        if not vulnerability:
            return 0.0
        
        try:
            # Find the asset for context
            asset = next((a for a in data.assets if a.asset_id == patch['asset_id']), None)
            asset_dict = asset.__dict__ if asset else {}
            
            # Use same format as risk calculator
            vuln_dict = {
                'exploit': getattr(vulnerability, 'exploit', False),
                'epss_score': getattr(vulnerability, 'epss', 0.0),
                'cvssV3Vector': getattr(vulnerability, 'cvssV3Vector', '')
            }
            return self.exploit_score_calc.calculate_exploit_score(vulnerability.cve_id, asset_dict, vuln_dict)
        except Exception as e:
            logger.warning(f"Could not calculate exploit score for {patch['vulnerability_id']}: {e}")
            return float(vulnerability.exploit)  # Fallback to direct value

# Legacy compatibility - keep the old class for backward compatibility
class PatchPrioritizer:
    """
    Legacy patch prioritizer class for backward compatibility
    
    This class maintains the old interface but delegates to the new specialized classes.
    """
    
    def __init__(self, risk_calculator=None, exploit_score_calc: ExploitScoreCalculator = None):
        """Initialize the legacy patch prioritizer"""
        if exploit_score_calc is None:
            exploit_score_calc = ExploitScoreCalculator()
        
        self.exploit_score_calc = exploit_score_calc
        self.risk_calculator = risk_calculator
        
        # Create specialized prioritizers
        self.asset_prioritizer = AssetPatchPrioritizer(exploit_score_calc)
        self.system_prioritizer_shortest = SystemPatchPrioritizerShortest(exploit_score_calc, risk_calculator)
        self.system_prioritizer_k_shortest = SystemPatchPrioritizerKShortest(exploit_score_calc, k_paths=3, risk_calculator=risk_calculator)
    
    def rank_patches(self, data: System, level: AnalysisLevel = AnalysisLevel.SYSTEM,
                    initial_risk: float = None, main_graph=None, comp_centrality_data: Dict[str, float] = None,
                    use_k_shortest: bool = False) -> List[Dict[str, Any]]:
        """
        Rank patches using the appropriate prioritizer
        
        Args:
            data: System data
            level: Analysis level (asset or system)
            initial_risk: Initial risk score (will calculate if not provided)
            main_graph: System network graph (for system-level analysis)
            comp_centrality_data: Component centrality data (for system-level analysis)
            use_k_shortest: Whether to use k-shortest path approach for system-level analysis
            
        Returns:
            List of ranked patches
        """
        if level == AnalysisLevel.ASSET:
            return self.asset_prioritizer.rank_patches(data, level, initial_risk, main_graph, comp_centrality_data)
        elif level == AnalysisLevel.SYSTEM:
            if use_k_shortest:
                return self.system_prioritizer_k_shortest.rank_patches(data, level, initial_risk, main_graph, comp_centrality_data)
            else:
                return self.system_prioritizer_shortest.rank_patches(data, level, initial_risk, main_graph, comp_centrality_data)
        else:
            raise ValueError(f"Unknown analysis level: {level}")
    
    def rank_vulnerabilities_by_cvss(self, data: System, level: AnalysisLevel) -> List[Dict[str, Any]]:
        """
        Rank vulnerabilities by CVSS score (legacy method)
        
        Args:
            data: System data
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
    