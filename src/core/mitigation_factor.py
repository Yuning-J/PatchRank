"""
Mitigation-Aware Indirect Risk Module
Implements Mitigation Factor (MF) calculation for edges as per revised paper.

Updated indirect risk equation:
R_indirect(v) = PL(v) * Σ_path (ImpactScore * PathWeight * MF_path)
MF_path = ∏ MF_edge
"""

import json
import yaml
import logging
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class MitigationFactorCalculator:
    """Calculate mitigation factors for network edges and paths"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize mitigation factor calculator
        
        Args:
            config_path: Path to mitigation configuration file (JSON/YAML)
        """
        self.mitigation_config = {}
        if config_path:
            self.load_mitigation_config(config_path)
        else:
            self._set_default_config()
    
    def load_mitigation_config(self, config_path: str) -> None:
        """
        Load mitigation configuration from JSON/YAML file
        
        Args:
            config_path: Path to configuration file
        """
        try:
            config_file = Path(config_path)
            if not config_file.exists():
                logger.warning(f"Config file {config_path} not found, using defaults")
                self._set_default_config()
                return
            
            with open(config_file, 'r') as f:
                if config_file.suffix.lower() in ['.yml', '.yaml']:
                    self.mitigation_config = yaml.safe_load(f)
                else:
                    self.mitigation_config = json.load(f)
                    
            logger.info(f"Loaded mitigation config from {config_path}")
            
        except Exception as e:
            logger.error(f"Error loading config {config_path}: {e}")
            self._set_default_config()
    
    def _set_default_config(self) -> None:
        """Set default mitigation configuration"""
        self.mitigation_config = {
            "ids_detection_rates": {
                "high": 0.9,
                "medium": 0.7,
                "low": 0.4,
                "none": 0.0
            },
            "segmentation_effectiveness": {
                "micro": 0.8,
                "macro": 0.6,
                "vlan": 0.4,
                "none": 0.0
            },
            "waf_protection": {
                "application": 0.8,
                "network": 0.6,
                "basic": 0.3,
                "none": 0.0
            },
            "zero_trust_coverage": {
                "full": 0.9,
                "partial": 0.6,
                "limited": 0.3,
                "none": 0.0
            },
            "default_weights": {
                "ids": 0.3,
                "segmentation": 0.3,
                "waf": 0.2,
                "zero_trust": 0.2
            }
        }
    
    def compute_mitigation_factor(self, edge: Dict[str, Any]) -> float:
        """
        Compute mitigation factor for a single edge
        
        Args:
            edge: Edge dictionary containing mitigation information
                  Expected keys: 'ids_level', 'segmentation', 'waf_type', 'zta_coverage'
        
        Returns:
            Mitigation factor MF_edge in range [0,1] where:
            - 0.0 = maximum mitigation (edge fully protected)
            - 1.0 = no mitigation (edge unprotected)
        """
        # Extract mitigation properties with defaults
        ids_level = edge.get('ids_level', 'none')
        segmentation = edge.get('segmentation', 'none') 
        waf_type = edge.get('waf_type', 'none')
        zta_coverage = edge.get('zta_coverage', 'none')
        
        # Get effectiveness values (higher = better protection)
        ids_effectiveness = self.mitigation_config['ids_detection_rates'].get(ids_level, 0.0)
        seg_effectiveness = self.mitigation_config['segmentation_effectiveness'].get(segmentation, 0.0)
        waf_effectiveness = self.mitigation_config['waf_protection'].get(waf_type, 0.0)
        zta_effectiveness = self.mitigation_config['zero_trust_coverage'].get(zta_coverage, 0.0)
        
        # Get weights
        weights = self.mitigation_config['default_weights']
        
        # Calculate combined effectiveness (weighted average)
        combined_effectiveness = (
            weights['ids'] * ids_effectiveness +
            weights['segmentation'] * seg_effectiveness +
            weights['waf'] * waf_effectiveness +
            weights['zero_trust'] * zta_effectiveness
        )
        
        # Convert to mitigation factor: higher effectiveness = lower MF
        # MF = 1 - effectiveness ensures MF ∈ [0,1] with desired semantics
        mitigation_factor = 1.0 - combined_effectiveness
        
        logger.debug(f"Edge MF: ids={ids_level}({ids_effectiveness:.2f}), "
                    f"seg={segmentation}({seg_effectiveness:.2f}), "
                    f"waf={waf_type}({waf_effectiveness:.2f}), "
                    f"zta={zta_coverage}({zta_effectiveness:.2f}) "
                    f"-> MF={mitigation_factor:.3f}")
        
        return mitigation_factor
    
    def compute_path_mitigation_factor(self, path_edges: List[Dict[str, Any]]) -> float:
        """
        Compute path mitigation factor as product of edge factors
        
        Args:
            path_edges: List of edge dictionaries representing path
        
        Returns:
            Path mitigation factor MF_path = ∏ MF_edge
        """
        if not path_edges:
            return 1.0  # No mitigation for empty path
        
        path_mf = 1.0
        for edge in path_edges:
            edge_mf = self.compute_mitigation_factor(edge)
            path_mf *= edge_mf
        
        logger.debug(f"Path MF: {len(path_edges)} edges -> MF_path={path_mf:.3f}")
        return path_mf
    
    def update_edge_with_mitigation(self, edge: Dict[str, Any], 
                                   mitigation_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update edge dictionary with mitigation information
        
        Args:
            edge: Base edge dictionary
            mitigation_data: Mitigation configuration for this edge
        
        Returns:
            Updated edge dictionary with mitigation factor
        """
        edge_copy = edge.copy()
        
        # Add mitigation properties
        edge_copy.update({
            'ids_level': mitigation_data.get('ids_level', 'none'),
            'segmentation': mitigation_data.get('segmentation', 'none'),
            'waf_type': mitigation_data.get('waf_type', 'none'),
            'zta_coverage': mitigation_data.get('zta_coverage', 'none')
        })
        
        # Calculate and store mitigation factor
        edge_copy['mf_edge'] = self.compute_mitigation_factor(edge_copy)
        
        return edge_copy
    
    def get_mitigation_summary(self) -> Dict[str, Any]:
        """
        Get summary of current mitigation configuration
        
        Returns:
            Summary dictionary with configuration details
        """
        return {
            'config_loaded': bool(self.mitigation_config),
            'mitigation_types': list(self.mitigation_config.keys()),
            'weights': self.mitigation_config.get('default_weights', {}),
            'total_combinations': (
                len(self.mitigation_config.get('ids_detection_rates', {})) *
                len(self.mitigation_config.get('segmentation_effectiveness', {})) *
                len(self.mitigation_config.get('waf_protection', {})) *
                len(self.mitigation_config.get('zero_trust_coverage', {}))
            )
        }


class MitigationAwareIndirectRisk:
    """Enhanced indirect risk calculator with mitigation factors"""
    
    def __init__(self, mitigation_calculator: MitigationFactorCalculator):
        """
        Initialize mitigation-aware indirect risk calculator
        
        Args:
            mitigation_calculator: MitigationFactorCalculator instance
        """
        self.mitigation_calc = mitigation_calculator
    
    def calculate_indirect_risk_with_mitigation(self, vulnerability: Dict[str, Any],
                                              paths: List[List[Dict[str, Any]]]) -> float:
        """
        Calculate indirect risk with mitigation factors
        
        Enhanced equation: R_indirect(v) = PL(v) * Σ_path (ImpactScore * PathWeight * MF_path)
        
        Args:
            vulnerability: Vulnerability information with propagation likelihood
            paths: List of attack paths, each path is list of edges
        
        Returns:
            Mitigation-aware indirect risk score
        """
        propagation_likelihood = vulnerability.get('propagation_likelihood', 0.0)
        impact_score = vulnerability.get('impact_score', vulnerability.get('impact', 0.0))
        
        if propagation_likelihood < 0.1:
            return 0.0  # Skip if very low propagation likelihood
        
        total_path_contribution = 0.0
        
        for path_edges in paths:
            if not path_edges:
                continue
            
            # Calculate base path weight (sum of edge weights)
            path_weight = sum(edge.get('weight', 1.0) for edge in path_edges)
            
            # Calculate path mitigation factor
            path_mf = self.mitigation_calc.compute_path_mitigation_factor(path_edges)
            
            # Path contribution with mitigation
            path_contribution = impact_score * path_weight * path_mf
            total_path_contribution += path_contribution
            
            logger.debug(f"Path: weight={path_weight:.2f}, MF={path_mf:.3f}, "
                        f"contribution={path_contribution:.3f}")
        
        # Apply propagation likelihood
        indirect_risk = propagation_likelihood * total_path_contribution
        
        logger.debug(f"Indirect risk: PL={propagation_likelihood:.3f} * "
                    f"total_contrib={total_path_contribution:.3f} = {indirect_risk:.3f}")
        
        return indirect_risk
    
    def compare_with_baseline(self, vulnerability: Dict[str, Any],
                            paths: List[List[Dict[str, Any]]]) -> Dict[str, float]:
        """
        Compare mitigation-aware risk with baseline (no mitigation)
        
        Args:
            vulnerability: Vulnerability information
            paths: List of attack paths
        
        Returns:
            Comparison dictionary with baseline and mitigated risks
        """
        # Calculate baseline (set all MF_edge = 1.0)
        baseline_paths = []
        for path in paths:
            baseline_path = []
            for edge in path:
                baseline_edge = edge.copy()
                baseline_edge['mf_edge'] = 1.0
                baseline_path.append(baseline_edge)
            baseline_paths.append(baseline_path)
        
        # Temporarily disable mitigation for baseline
        temp_config = self.mitigation_calc.mitigation_config
        self.mitigation_calc.mitigation_config = {
            "ids_detection_rates": {"none": 0.0},
            "segmentation_effectiveness": {"none": 0.0},
            "waf_protection": {"none": 0.0},
            "zero_trust_coverage": {"none": 0.0},
            "default_weights": {"ids": 0.25, "segmentation": 0.25, "waf": 0.25, "zero_trust": 0.25}
        }
        
        baseline_risk = self.calculate_indirect_risk_with_mitigation(vulnerability, baseline_paths)
        
        # Restore config and calculate mitigated risk
        self.mitigation_calc.mitigation_config = temp_config
        mitigated_risk = self.calculate_indirect_risk_with_mitigation(vulnerability, paths)
        
        reduction_percentage = ((baseline_risk - mitigated_risk) / baseline_risk * 100) if baseline_risk > 0 else 0.0
        
        return {
            'baseline_risk': baseline_risk,
            'mitigated_risk': mitigated_risk,
            'risk_reduction': baseline_risk - mitigated_risk,
            'reduction_percentage': reduction_percentage
        }


def create_sample_mitigation_config() -> Dict[str, Any]:
    """
    Create sample mitigation configuration for testing/demo
    
    Returns:
        Sample configuration dictionary
    """
    return {
        "ids_detection_rates": {
            "high": 0.9,      # Advanced IDS with ML/behavioral analysis
            "medium": 0.7,    # Standard signature-based IDS
            "low": 0.4,       # Basic pattern matching
            "none": 0.0       # No IDS deployed
        },
        "segmentation_effectiveness": {
            "micro": 0.8,     # Micro-segmentation with zero-trust
            "macro": 0.6,     # Network-level segmentation
            "vlan": 0.4,      # VLAN-based segmentation
            "none": 0.0       # Flat network
        },
        "waf_protection": {
            "application": 0.8,  # Application-aware WAF
            "network": 0.6,      # Network-level filtering
            "basic": 0.3,        # Basic packet filtering
            "none": 0.0          # No WAF
        },
        "zero_trust_coverage": {
            "full": 0.9,      # Complete ZTA implementation
            "partial": 0.6,   # Limited ZTA (critical assets only)
            "limited": 0.3,   # Basic identity verification
            "none": 0.0       # Traditional perimeter security
        },
        "default_weights": {
            "ids": 0.3,
            "segmentation": 0.3,
            "waf": 0.2,
            "zero_trust": 0.2
        }
    }


def save_sample_config(file_path: str = "data/mitigation_config.yaml") -> None:
    """
    Save sample mitigation configuration to file
    
    Args:
        file_path: Path where to save the configuration
    """
    config = create_sample_mitigation_config()
    
    # Create directory if it doesn't exist
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
    
    with open(file_path, 'w') as f:
        yaml.dump(config, f, default_flow_style=False, indent=2)
    
    logger.info(f"Sample mitigation config saved to {file_path}")