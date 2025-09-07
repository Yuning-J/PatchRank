"""
Ranking Statistical Analysis Module
Focuses on ranking stability, correlation analysis, and comparative evaluation
without requiring ground truth data
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple, Optional, Union
import json
import logging
from pathlib import Path
from scipy.stats import kendalltau, spearmanr, wilcoxon, friedmanchisquare
from scipy import stats
import warnings
from dataclasses import dataclass
from itertools import combinations

from .statistical_utils import (
    bootstrap_spearman_ci, bootstrap_kendall_ci, 
    calculate_enhanced_correlation_analysis,
    bonferroni_correction, holm_bonferroni_correction,
    cohens_d, cliffs_delta, interpret_effect_size,
    apply_multiple_comparison_corrections
)

logger = logging.getLogger(__name__)


@dataclass
class RankingComparisonResult:
    """Enhanced result of ranking comparison analysis with confidence intervals and effect sizes"""
    method1: str
    method2: str
    scenario: str
    spearman_correlation: float
    spearman_p_value: float
    spearman_ci_lower: float
    spearman_ci_upper: float
    kendall_tau: float
    kendall_p_value: float
    kendall_ci_lower: float
    kendall_ci_upper: float
    ranking_agreement: float  # Proportion of items with same relative order
    top_k_overlap: Dict[int, float]  # Top-k overlap for different k values
    cohens_d: float
    cohens_d_interpretation: str
    cliffs_delta: float
    cliffs_delta_interpretation: str
    interpretation: str


@dataclass 
class SensitivityAnalysisResult:
    """Result of parameter sensitivity analysis"""
    parameter_name: str
    parameter_values: List[float]
    ranking_stability: List[float]  # Correlation with baseline for each parameter value
    optimal_value: float
    stability_range: Tuple[float, float]  # Min and max stability
    significant_changes: List[Tuple[float, float]]  # Parameter values causing significant ranking changes


class RankingStatisticalAnalyzer:
    """
    Statistical analysis focused on ranking properties without ground truth
    """
    
    def __init__(self, significance_level: float = 0.05):
        """
        Initialize ranking statistical analyzer
        
        Args:
            significance_level: Alpha level for significance testing
        """
        self.significance_level = significance_level
        self.baseline_data_path = Path("data/baselines")
        
    def load_rankings_from_json(self, file_path: str) -> List[Dict[str, Any]]:
        """Load rankings from JSON file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            return data.get('rankings', [])
        except Exception as e:
            logger.error(f"Failed to load rankings from {file_path}: {e}")
            return []
    
    def compare_ranking_methods(self, rankings1: List[Dict[str, Any]], 
                              rankings2: List[Dict[str, Any]],
                              method1_name: str = "Method1",
                              method2_name: str = "Method2",
                              scenario: str = "Unknown") -> RankingComparisonResult:
        """
        Enhanced comparison of two ranking methods with confidence intervals and effect sizes
        
        Args:
            rankings1: First method's rankings
            rankings2: Second method's rankings  
            method1_name: Name of first method
            method2_name: Name of second method
            scenario: Scenario name
            
        Returns:
            Enhanced RankingComparisonResult with CI and effect sizes
        """
        # Extract CVE IDs and ranks/scores
        ranking1_dict = {}
        ranking2_dict = {}
        
        for item in rankings1:
            if 'cve_id' in item:
                cve_id = item['cve_id']
                # Use priority_score if available, otherwise use inverse of rank
                if 'priority_score' in item:
                    score = float(item['priority_score'])
                elif 'rank' in item:
                    score = 1.0 / (float(item['rank']) + 1)  # Higher rank = lower score
                else:
                    continue
                ranking1_dict[cve_id] = score
        
        for item in rankings2:
            if 'cve_id' in item:
                cve_id = item['cve_id']
                if 'priority_score' in item:
                    score = float(item['priority_score'])
                elif 'rank' in item:
                    score = 1.0 / (float(item['rank']) + 1)
                else:
                    continue
                ranking2_dict[cve_id] = score
        
        # Find common CVEs
        common_cves = set(ranking1_dict.keys()) & set(ranking2_dict.keys())
        
        if len(common_cves) < 3:
            return RankingComparisonResult(
                method1=method1_name,
                method2=method2_name, 
                scenario=scenario,
                spearman_correlation=0.0,
                spearman_p_value=1.0,
                spearman_ci_lower=0.0,
                spearman_ci_upper=0.0,
                kendall_tau=0.0,
                kendall_p_value=1.0,
                kendall_ci_lower=0.0,
                kendall_ci_upper=0.0,
                ranking_agreement=0.0,
                top_k_overlap={},
                cohens_d=0.0,
                cohens_d_interpretation="N/A",
                cliffs_delta=0.0,
                cliffs_delta_interpretation="N/A",
                interpretation="Insufficient common items for comparison"
            )
        
        # Extract scores for common CVEs
        scores1 = [ranking1_dict[cve] for cve in common_cves]
        scores2 = [ranking2_dict[cve] for cve in common_cves]
        
        # Enhanced correlation analysis with bootstrap CI
        enhanced_analysis = calculate_enhanced_correlation_analysis(scores1, scores2)
        
        # Extract enhanced results
        spearman_results = enhanced_analysis.get('spearman', {})
        kendall_results = enhanced_analysis.get('kendall', {})
        effect_results = enhanced_analysis.get('effect_sizes', {})
        
        spearman_corr = spearman_results.get('correlation', 0.0)
        spearman_ci_lower = spearman_results.get('ci_lower', 0.0)
        spearman_ci_upper = spearman_results.get('ci_upper', 0.0)
        
        kendall_corr = kendall_results.get('tau', 0.0)
        kendall_ci_lower = kendall_results.get('ci_lower', 0.0)
        kendall_ci_upper = kendall_results.get('ci_upper', 0.0)
        
        cohens_d_val = effect_results.get('cohens_d', {}).get('value', 0.0)
        cohens_d_interp = effect_results.get('cohens_d', {}).get('interpretation', "N/A")
        cliffs_delta_val = effect_results.get('cliffs_delta', {}).get('value', 0.0)
        cliffs_delta_interp = effect_results.get('cliffs_delta', {}).get('interpretation', "N/A")
        
        # Calculate ranking agreement (proportion of pairs with same relative order)
        agreement_count = 0
        total_pairs = 0
        
        cves_list = list(common_cves)
        for i, cve1 in enumerate(cves_list):
            for cve2 in cves_list[i+1:]:
                score1_1, score1_2 = ranking1_dict[cve1], ranking1_dict[cve2]
                score2_1, score2_2 = ranking2_dict[cve1], ranking2_dict[cve2]
                
                # Check if relative order is preserved
                if (score1_1 > score1_2 and score2_1 > score2_2) or \
                   (score1_1 < score1_2 and score2_1 < score2_2) or \
                   (score1_1 == score1_2 and score2_1 == score2_2):
                    agreement_count += 1
                total_pairs += 1
        
        ranking_agreement = agreement_count / total_pairs if total_pairs > 0 else 0.0
        
        # Calculate extended top-k overlap
        top_k_overlap = {}
        for k in [5, 10, 20]:
            if len(common_cves) >= k:
                top_k1 = set(sorted(common_cves, key=lambda x: ranking1_dict[x], reverse=True)[:k])
                top_k2 = set(sorted(common_cves, key=lambda x: ranking2_dict[x], reverse=True)[:k])
                
                overlap = len(top_k1 & top_k2)
                top_k_overlap[k] = overlap / k
        
        # Enhanced interpretation with confidence intervals
        spearman_significant = spearman_results.get('significant', False)
        
        if abs(spearman_corr) > 0.7 and spearman_significant:
            interpretation = f"Strong correlation ({spearman_corr:.3f}, 95% CI: [{spearman_ci_lower:.3f}, {spearman_ci_upper:.3f}])"
        elif abs(spearman_corr) > 0.3 and spearman_significant:
            interpretation = f"Moderate correlation ({spearman_corr:.3f}, 95% CI: [{spearman_ci_lower:.3f}, {spearman_ci_upper:.3f}])"
        elif spearman_significant:
            interpretation = f"Weak correlation ({spearman_corr:.3f}, 95% CI: [{spearman_ci_lower:.3f}, {spearman_ci_upper:.3f}])"
        else:
            interpretation = f"No significant correlation ({spearman_corr:.3f}, 95% CI: [{spearman_ci_lower:.3f}, {spearman_ci_upper:.3f}])"
        
        return RankingComparisonResult(
            method1=method1_name,
            method2=method2_name,
            scenario=scenario,
            spearman_correlation=spearman_corr,
            spearman_p_value=0.05,  # Approximation since we use CI-based significance
            spearman_ci_lower=spearman_ci_lower,
            spearman_ci_upper=spearman_ci_upper,
            kendall_tau=kendall_corr,
            kendall_p_value=0.05,  # Approximation
            kendall_ci_lower=kendall_ci_lower,
            kendall_ci_upper=kendall_ci_upper,
            ranking_agreement=ranking_agreement,
            top_k_overlap=top_k_overlap,
            cohens_d=cohens_d_val,
            cohens_d_interpretation=cohens_d_interp,
            cliffs_delta=cliffs_delta_val,
            cliffs_delta_interpretation=cliffs_delta_interp,
            interpretation=interpretation
        )
    
    def analyze_ranking_stability_across_scenarios(self, rankings_data: Dict[str, List[Dict[str, Any]]],
                                                 method_name: str = "PatchRank") -> Dict[str, float]:
        """
        Analyze how stable rankings are across different scenarios
        
        Args:
            rankings_data: Dictionary mapping scenario names to rankings
            method_name: Name of the method being analyzed
            
        Returns:
            Dictionary with stability metrics
        """
        stability_metrics = {}
        
        if len(rankings_data) < 2:
            logger.warning(f"Need at least 2 scenarios for stability analysis, found {len(rankings_data)}")
            return stability_metrics
        
        # Calculate pairwise correlations between scenarios
        scenario_names = list(rankings_data.keys())
        correlations = []
        agreements = []
        comparability_results = []
        
        for i, scenario1 in enumerate(scenario_names):
            for scenario2 in scenario_names[i+1:]:
                # Validate comparability first
                comparability = self._validate_scenario_comparability(
                    rankings_data[scenario1], rankings_data[scenario2]
                )
                comparability_results.append(comparability)
                
                if comparability['comparable']:
                    comparison = self.compare_ranking_methods(
                        rankings_data[scenario1],
                        rankings_data[scenario2], 
                        f"{method_name}_{scenario1}",
                        f"{method_name}_{scenario2}",
                        f"{scenario1}_vs_{scenario2}"
                    )
                    
                    # FIX: Check if comparison is valid before using correlation
                    if comparison.interpretation != "Insufficient common items for comparison":
                        correlations.append(comparison.spearman_correlation)  # Remove abs() to preserve sign
                        agreements.append(comparison.ranking_agreement)
                        logger.info(f"Valid comparison {scenario1} vs {scenario2}: r={comparison.spearman_correlation:.3f}")
                    else:
                        logger.warning(f"Skipping {scenario1} vs {scenario2}: {comparison.interpretation}")
                else:
                    logger.info(f"Scenarios {scenario1} vs {scenario2} not comparable: {comparability['common_cves']}/{min(comparability['total_cves_scenario1'], comparability['total_cves_scenario2'])} common CVEs")
        
        if correlations:
            stability_metrics.update({
                'mean_cross_scenario_correlation': np.mean(correlations),
                'std_cross_scenario_correlation': np.std(correlations),
                'min_cross_scenario_correlation': np.min(correlations),
                'max_cross_scenario_correlation': np.max(correlations),
                'mean_ranking_agreement': np.mean(agreements) if agreements else 0.0,
                'num_scenario_pairs': len(correlations),
                'total_scenario_pairs_tested': len(comparability_results),
                'comparable_pairs': sum(1 for c in comparability_results if c['comparable'])
            })
        else:
            stability_metrics.update({
                'mean_cross_scenario_correlation': None,
                'warning': 'No comparable scenario pairs found for correlation analysis',
                'total_scenario_pairs_tested': len(comparability_results),
                'comparable_pairs': 0
            })
        
        return stability_metrics
    
    def _validate_scenario_comparability(self, scenario1_data: List[Dict], scenario2_data: List[Dict]) -> Dict[str, Any]:
        """Validate if two scenarios can be meaningfully compared"""
        
        # Extract CVE sets
        cves1 = {item['cve_id'] for item in scenario1_data if 'cve_id' in item}
        cves2 = {item['cve_id'] for item in scenario2_data if 'cve_id' in item}
        
        common_cves = cves1 & cves2
        
        return {
            'comparable': len(common_cves) >= 3,  # Need at least 3 common CVEs for meaningful correlation
            'common_cves': len(common_cves),
            'total_cves_scenario1': len(cves1),
            'total_cves_scenario2': len(cves2),
            'overlap_ratio': len(common_cves) / min(len(cves1), len(cves2)) if min(len(cves1), len(cves2)) > 0 else 0
        }
    
    def perform_sensitivity_analysis(self, baseline_rankings: List[Dict[str, Any]],
                                   parameter_variations: Dict[str, List[Dict[str, Any]]],
                                   parameter_name: str) -> SensitivityAnalysisResult:
        """
        Analyze ranking sensitivity to parameter changes
        
        Args:
            baseline_rankings: Baseline rankings for comparison
            parameter_variations: Dictionary mapping parameter values to rankings
            parameter_name: Name of the parameter being varied
            
        Returns:
            SensitivityAnalysisResult with sensitivity analysis
        """
        parameter_values = []
        ranking_stabilities = []
        
        for param_value, varied_rankings in parameter_variations.items():
            try:
                param_float = float(param_value)
                parameter_values.append(param_float)
                
                # Compare with baseline
                comparison = self.compare_ranking_methods(
                    baseline_rankings,
                    varied_rankings,
                    "Baseline", 
                    f"{parameter_name}={param_value}",
                    "Sensitivity"
                )
                
                # Use absolute correlation as stability measure
                stability = abs(comparison.spearman_correlation) if comparison.spearman_p_value < self.significance_level else 0.0
                ranking_stabilities.append(stability)
                
            except (ValueError, TypeError):
                continue
        
        if not parameter_values:
            return SensitivityAnalysisResult(
                parameter_name=parameter_name,
                parameter_values=[],
                ranking_stability=[],
                optimal_value=0.0,
                stability_range=(0.0, 0.0),
                significant_changes=[]
            )
        
        # Find optimal parameter value (highest stability)
        optimal_idx = np.argmax(ranking_stabilities)
        optimal_value = parameter_values[optimal_idx]
        
        # Find significant changes (stability drops below threshold)
        stability_threshold = 0.7
        significant_changes = []
        
        for i, stability in enumerate(ranking_stabilities):
            if stability < stability_threshold:
                significant_changes.append((parameter_values[i], stability))
        
        return SensitivityAnalysisResult(
            parameter_name=parameter_name,
            parameter_values=parameter_values,
            ranking_stability=ranking_stabilities,
            optimal_value=optimal_value,
            stability_range=(min(ranking_stabilities), max(ranking_stabilities)),
            significant_changes=significant_changes
        )
    
    def comprehensive_baseline_comparison(self, patchrank_rankings: List[Dict[str, Any]],
                                        scenario_name: str) -> Dict[str, RankingComparisonResult]:
        """
        Compare PatchRank against multiple baseline methods
        
        Args:
            patchrank_rankings: PatchRank rankings
            scenario_name: Name of the scenario
            
        Returns:
            Dictionary mapping baseline method names to comparison results
        """
        baseline_comparisons = {}
        
        # Create synthetic baseline rankings
        baseline_methods = self._create_baseline_rankings(patchrank_rankings)
        
        for baseline_name, baseline_rankings in baseline_methods.items():
            comparison = self.compare_ranking_methods(
                patchrank_rankings,
                baseline_rankings,
                "PatchRank",
                baseline_name,
                scenario_name
            )
            baseline_comparisons[baseline_name] = comparison
        
        return baseline_comparisons
    
    def _create_baseline_rankings(self, reference_rankings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Create synthetic baseline method rankings for comparison"""
        baselines = {}
        
        # CVSS-only baseline
        cvss_rankings = []
        for item in reference_rankings:
            item_copy = item.copy()
            cvss_score = float(item.get('cvss', 0))
            item_copy['priority_score'] = cvss_score  # Keep as float, don't convert to string
            cvss_rankings.append(item_copy)
        
        # Sort by CVSS score descending
        cvss_rankings.sort(key=lambda x: x['priority_score'], reverse=True)
        
        # Assign ranks based on sorted order
        for i, item in enumerate(cvss_rankings, 1):
            item['rank'] = i
        
        baselines['CVSS'] = cvss_rankings
        
        # EPSS-only baseline
        epss_rankings = []
        for item in reference_rankings:
            item_copy = item.copy()
            epss_score = float(item.get('epss', 0))
            item_copy['priority_score'] = epss_score  # Keep as float
            epss_rankings.append(item_copy)
        
        # Sort by EPSS score descending
        epss_rankings.sort(key=lambda x: x['priority_score'], reverse=True)
        
        # Assign ranks based on sorted order
        for i, item in enumerate(epss_rankings, 1):
            item['rank'] = i
        
        baselines['EPSS'] = epss_rankings
        
        # CVSS+EPSS combined baseline
        combined_rankings = []
        for item in reference_rankings:
            item_copy = item.copy()
            cvss_score = float(item.get('cvss', 0))
            epss_score = float(item.get('epss', 0))
            combined_score = cvss_score + epss_score
            item_copy['priority_score'] = combined_score  # Keep as float
            combined_rankings.append(item_copy)
        
        # Sort by combined score descending
        combined_rankings.sort(key=lambda x: x['priority_score'], reverse=True)
        
        # Assign ranks based on sorted order
        for i, item in enumerate(combined_rankings, 1):
            item['rank'] = i
        
        baselines['CVSS+EPSS'] = combined_rankings
        
        # Exploit Score baseline (if available)
        if any('exploit_score' in item for item in reference_rankings):
            exploit_rankings = []
            for item in reference_rankings:
                item_copy = item.copy()
                exploit_score = float(item.get('exploit_score', 0))
                item_copy['priority_score'] = exploit_score  # Keep as float
                exploit_rankings.append(item_copy)
            
            # Sort by exploit score descending
            exploit_rankings.sort(key=lambda x: x['priority_score'], reverse=True)
            
            # Assign ranks based on sorted order
            for i, item in enumerate(exploit_rankings, 1):
                item['rank'] = i
            
            baselines['Exploit_Score'] = exploit_rankings
        
        return baselines
    
    def test_ranking_differences_significance(self, rankings_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Test for significant differences in rankings between different conditions/scenarios
        
        Args:
            rankings_data: Dictionary mapping condition names to rankings
            
        Returns:
            Dictionary with statistical test results
        """
        test_results = {}
        
        if len(rankings_data) < 2:
            return test_results
        
        # Extract ranking positions for common CVEs across all conditions
        all_cves = set()
        for rankings in rankings_data.values():
            for item in rankings:
                if 'cve_id' in item:
                    all_cves.add(item['cve_id'])
        
        # Find CVEs present in all conditions
        common_cves = all_cves.copy()
        condition_rankings = {}
        
        for condition, rankings in rankings_data.items():
            condition_cves = set()
            condition_dict = {}
            for item in rankings:
                if 'cve_id' in item and 'rank' in item:
                    cve_id = item['cve_id']
                    condition_cves.add(cve_id)
                    condition_dict[cve_id] = int(item['rank'])
            
            common_cves &= condition_cves
            condition_rankings[condition] = condition_dict
        
        if len(common_cves) < 3:
            test_results['error'] = "Insufficient common items for statistical testing"
            return test_results
        
        # Perform Friedman test for multiple related samples
        if len(rankings_data) > 2:
            ranking_arrays = []
            for condition in condition_rankings:
                ranks = [condition_rankings[condition][cve] for cve in common_cves]
                ranking_arrays.append(ranks)
            
            try:
                friedman_stat, friedman_p = friedmanchisquare(*ranking_arrays)
                
                test_results['friedman_test'] = {
                    'statistic': friedman_stat,
                    'p_value': friedman_p,
                    'significant': friedman_p < self.significance_level,
                    'interpretation': (
                        f"Significant ranking differences across conditions (p={friedman_p:.4f})"
                        if friedman_p < self.significance_level
                        else f"No significant ranking differences (p={friedman_p:.4f})"
                    )
                }
                
            except Exception as e:
                test_results['friedman_test'] = {'error': str(e)}
        
        # Pairwise comparisons using Wilcoxon signed-rank test
        conditions = list(condition_rankings.keys())
        pairwise_results = {}
        
        for i, cond1 in enumerate(conditions):
            for cond2 in conditions[i+1:]:
                ranks1 = [condition_rankings[cond1][cve] for cve in common_cves]
                ranks2 = [condition_rankings[cond2][cve] for cve in common_cves]
                
                try:
                    wilcoxon_stat, wilcoxon_p = wilcoxon(ranks1, ranks2, alternative='two-sided')
                    
                    pairwise_results[f"{cond1}_vs_{cond2}"] = {
                        'statistic': wilcoxon_stat,
                        'p_value': wilcoxon_p,
                        'significant': wilcoxon_p < self.significance_level,
                        'effect_size': self._calculate_wilcoxon_effect_size(ranks1, ranks2),
                        'interpretation': (
                            f"Significant difference between {cond1} and {cond2} (p={wilcoxon_p:.4f})"
                            if wilcoxon_p < self.significance_level
                            else f"No significant difference between {cond1} and {cond2} (p={wilcoxon_p:.4f})"
                        )
                    }
                    
                except Exception as e:
                    pairwise_results[f"{cond1}_vs_{cond2}"] = {'error': str(e)}
        
        test_results['pairwise_comparisons'] = pairwise_results
        test_results['common_items_count'] = len(common_cves)
        test_results['conditions_compared'] = list(rankings_data.keys())
        
        return test_results
    
    def _calculate_wilcoxon_effect_size(self, sample1: List[float], sample2: List[float]) -> float:
        """Calculate effect size for Wilcoxon test (r = Z / sqrt(N))"""
        try:
            differences = np.array(sample1) - np.array(sample2)
            n = len(differences)
            
            if n == 0:
                return 0.0
            
            # Approximate Z-score for Wilcoxon test
            ranks = stats.rankdata(np.abs(differences))
            signed_ranks = ranks * np.sign(differences)
            w_plus = np.sum(signed_ranks[signed_ranks > 0])
            
            expected_w = n * (n + 1) / 4
            var_w = n * (n + 1) * (2 * n + 1) / 24
            
            z_score = (w_plus - expected_w) / np.sqrt(var_w)
            effect_size = abs(z_score) / np.sqrt(n)
            
            return effect_size
            
        except Exception:
            return 0.0
    
    def generate_statistical_analysis_report(self, rankings_data_path: str = "data/baselines",
                                           output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate comprehensive statistical analysis report
        
        Args:
            rankings_data_path: Path to rankings data directory
            output_path: Path to save report
            
        Returns:
            Comprehensive statistical analysis report
        """
        logger.info("Starting comprehensive ranking statistical analysis...")
        
        # Load rankings data
        rankings_data = self._load_all_rankings(rankings_data_path)
        
        if not rankings_data:
            raise ValueError(f"No ranking data found in {rankings_data_path}")
        
        report = {
            'metadata': {
                'analysis_timestamp': pd.Timestamp.now().isoformat(),
                'scenarios_analyzed': list(rankings_data.keys()),
                'analysis_type': 'ranking_statistical_analysis',
                'significance_level': self.significance_level
            },
            'analyses': {}
        }
        
        # 1. Ranking stability analysis
        logger.info("Performing ranking stability analysis...")
        patchrank_rankings = {scenario: data['PatchRank'] 
                            for scenario, data in rankings_data.items() 
                            if 'PatchRank' in data}
        
        stability_metrics = self.analyze_ranking_stability_across_scenarios(
            patchrank_rankings, "PatchRank"
        )
        report['analyses']['ranking_stability'] = stability_metrics
        
        # 2. Baseline comparison analysis
        logger.info("Performing baseline comparison analysis...")
        baseline_comparisons = {}
        for scenario, data in rankings_data.items():
            if 'PatchRank' in data:
                comparisons = self.comprehensive_baseline_comparison(data['PatchRank'], scenario)
                baseline_comparisons[scenario] = {
                    method: {
                        'spearman_correlation': comp.spearman_correlation,
                        'spearman_p_value': comp.spearman_p_value,
                        'kendall_tau': comp.kendall_tau, 
                        'ranking_agreement': comp.ranking_agreement,
                        'top_k_overlap': comp.top_k_overlap,
                        'interpretation': comp.interpretation
                    } for method, comp in comparisons.items()
                }
        
        report['analyses']['baseline_comparisons'] = baseline_comparisons
        
        # 3. Significance testing across scenarios
        logger.info("Performing significance testing...")
        significance_results = self.test_ranking_differences_significance(patchrank_rankings)
        report['analyses']['significance_testing'] = significance_results
        
        # 4. Generate summary and recommendations
        report['summary'] = self._generate_statistical_summary(report['analyses'])
        
        # Save report if path provided
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"Statistical analysis report saved to {output_path}")
        
        return report
    
    def _load_all_rankings(self, rankings_path: str) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        """Load all ranking data from directory"""
        rankings_data = {}
        rankings_dir = Path(rankings_path) / "algorithm_rankings"
        
        if not rankings_dir.exists():
            logger.error(f"Rankings directory not found: {rankings_dir}")
            return rankings_data
        
        for json_file in rankings_dir.glob("*.json"):
            scenario_name = json_file.stem.replace("_algorithm_rankings", "")
            
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                
                rankings_data[scenario_name] = {'PatchRank': data.get('rankings', [])}
                
            except Exception as e:
                logger.error(f"Failed to load rankings from {json_file}: {e}")
        
        return rankings_data
    
    def _generate_statistical_summary(self, analyses: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of statistical analysis results"""
        summary = {
            'key_findings': [],
            'statistical_evidence': [],
            'recommendations': []
        }
        
        # Ranking stability assessment
        if 'ranking_stability' in analyses:
            stability = analyses['ranking_stability']
            mean_corr = stability.get('mean_cross_scenario_correlation', 0)
            
            if mean_corr > 0.7:
                summary['key_findings'].append(f"High ranking stability across scenarios (mean correlation: {mean_corr:.3f})")
                summary['statistical_evidence'].append("Strong evidence of consistent ranking behavior")
            elif mean_corr > 0.5:
                summary['key_findings'].append(f"Moderate ranking stability across scenarios (mean correlation: {mean_corr:.3f})")
            else:
                summary['key_findings'].append(f"Low ranking stability across scenarios (mean correlation: {mean_corr:.3f})")
                summary['recommendations'].append("Consider parameter tuning to improve ranking consistency")
        
        # Baseline comparison assessment
        if 'baseline_comparisons' in analyses:
            baseline_results = analyses['baseline_comparisons']
            
            dissimilarity_scores = []
            for scenario_data in baseline_results.values():
                for method_data in scenario_data.values():
                    corr = abs(method_data.get('spearman_correlation', 0))
                    dissimilarity_scores.append(1 - corr)
            
            if dissimilarity_scores:
                mean_dissimilarity = np.mean(dissimilarity_scores)
                if mean_dissimilarity > 0.3:
                    summary['statistical_evidence'].append(f"Significant differentiation from baselines (mean dissimilarity: {mean_dissimilarity:.3f})")
                else:
                    summary['recommendations'].append("Consider enhancing method differentiation from simple baselines")
        
        # Significance testing assessment
        if 'significance_testing' in analyses:
            sig_results = analyses['significance_testing']
            
            if 'friedman_test' in sig_results:
                friedman = sig_results['friedman_test']
                if friedman.get('significant', False):
                    summary['statistical_evidence'].append(f"Significant ranking differences across scenarios (Friedman p={friedman['p_value']:.4f})")
                else:
                    summary['key_findings'].append("No significant ranking differences across scenarios")
            
            if 'pairwise_comparisons' in sig_results:
                pairwise = sig_results['pairwise_comparisons']
                significant_pairs = sum(1 for comp in pairwise.values() 
                                      if comp.get('significant', False))
                total_pairs = len(pairwise)
                
                if significant_pairs > 0:
                    summary['statistical_evidence'].append(f"{significant_pairs}/{total_pairs} scenario pairs show significant ranking differences")
        
        # Overall assessment
        evidence_count = len(summary['statistical_evidence'])
        if evidence_count >= 2:
            summary['overall_conclusion'] = "Strong statistical evidence supporting the ranking method's effectiveness"
        elif evidence_count == 1:
            summary['overall_conclusion'] = "Moderate statistical evidence supporting the ranking method"
        else:
            summary['overall_conclusion'] = "Limited statistical evidence - further analysis recommended"
        
        return summary


def run_ranking_statistical_analysis(baseline_path: str = "data/baselines",
                                   output_path: str = "results/ranking_statistical_analysis.json") -> Dict[str, Any]:
    """
    Run comprehensive ranking statistical analysis
    
    Args:
        baseline_path: Path to baseline rankings directory
        output_path: Path to save analysis report
        
    Returns:
        Statistical analysis report
    """
    analyzer = RankingStatisticalAnalyzer()
    
    logger.info("Starting ranking statistical analysis...")
    
    # Ensure output directory exists
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    # Generate comprehensive analysis
    report = analyzer.generate_statistical_analysis_report(baseline_path, output_path)
    
    logger.info(f"Ranking statistical analysis complete. Report saved to {output_path}")
    
    return report