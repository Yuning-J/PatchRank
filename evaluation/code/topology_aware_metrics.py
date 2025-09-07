"""
Topology-Aware Evaluation Metrics for PatchRank
Academically sound metrics without requiring ground truth
Focus on ranking consistency, topology differentiation, and risk coherence
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple, Optional, Union
import json
import logging
from pathlib import Path
from scipy.stats import kendalltau, spearmanr, pearsonr
from scipy.spatial.distance import cosine
import warnings

from .statistical_utils import calculate_enhanced_correlation_analysis
from .evaluation_metrics import (
    calculate_ndcg, calculate_extended_top_k_analysis, 
    calculate_comprehensive_ndcg_analysis
)

logger = logging.getLogger(__name__)


class TopologyAwareMetrics:
    """
    Academically sound evaluation metrics that don't require ground truth
    Focus on topology differentiation, ranking consistency, and risk coherence
    """
    
    def __init__(self):
        """Initialize topology-aware metrics calculator"""
        self.baseline_data_path = Path("data/baselines")
        
    def load_rankings_from_baselines(self) -> Dict[str, Dict[str, Any]]:
        """
        Load all rankings from the scenario-based baselines directory structure
        
        Returns:
            Dictionary with scenario -> method -> rankings structure
        """
        rankings_data = {}
        
        # Map scenario directory names to clean scenario names
        scenario_mapping = {
            'scenario1_openPLC': 'openPLC',
            'scenario2_NP1_NP2': 'NP1_NP2', 
            'scenario3_ICS': 'ICS',
            'scenario4_ES': 'ES'
        }
        
        # Load from scenario directories
        for scenario_dir in self.baseline_data_path.iterdir():
            if not scenario_dir.is_dir() or scenario_dir.name.startswith('.'):
                continue
                
            dir_name = scenario_dir.name
            if dir_name == 'algorithm_rankings':
                continue  # Skip old structure
                
            scenario_name = scenario_mapping.get(dir_name, dir_name)
            rankings_data[scenario_name] = {}
            
            logger.info(f"Processing scenario directory: {dir_name} -> {scenario_name}")
            
            # Load all baseline files in this scenario directory
            for json_file in scenario_dir.glob("*.json"):
                try:
                    with open(json_file, 'r') as f:
                        data = json.load(f)
                        
                    baseline_name = json_file.stem
                    
                    # Handle different baseline file formats
                    if 'algorithm_rankings' in baseline_name:
                        # Our algorithm results - distinguish NP1/NP2
                        if 'NP1_algorithm_rankings' in baseline_name:
                            method_name = 'PatchRank_NP1'
                        elif 'NP2_algorithm_rankings' in baseline_name:
                            method_name = 'PatchRank_NP2'
                        else:
                            method_name = 'PatchRank'
                        
                        if isinstance(data, dict) and 'rankings' in data:
                            rankings_data[scenario_name][method_name] = data['rankings']
                            logger.info(f"Loaded {method_name} with {len(data['rankings'])} rankings")
                    
                    elif 'cvss_base_rankings' in baseline_name:
                        # CVSS base score only
                        method_name = 'CVSS_Base'
                        if isinstance(data, dict) and 'rankings' in data:
                            rankings_data[scenario_name][method_name] = data['rankings']
                            logger.info(f"Loaded CVSS_Base with {len(data['rankings'])} rankings")
                    
                    elif 'cvss_be_rankings' in baseline_name:
                        # CVSS with environmental scores
                        if 'NP1' in baseline_name:
                            method_name = 'CVSS_BE_NP1'
                        elif 'NP2' in baseline_name:
                            method_name = 'CVSS_BE_NP2'
                        else:
                            method_name = 'CVSS_BE'
                            
                        if isinstance(data, dict) and 'rankings' in data:
                            rankings_data[scenario_name][method_name] = data['rankings']
                            logger.info(f"Loaded {method_name} with {len(data['rankings'])} rankings")
                    
                    elif 'epss_rankings' in baseline_name:
                        # EPSS only
                        method_name = 'EPSS'
                        if isinstance(data, dict) and 'rankings' in data:
                            rankings_data[scenario_name][method_name] = data['rankings']
                            logger.info(f"Loaded EPSS with {len(data['rankings'])} rankings")
                    
                    elif 'paper' in baseline_name and 'baselines' in baseline_name:
                        # Paper baseline methods (multiple methods per file)
                        if isinstance(data, dict) and 'baselines' in data:
                            for method_name, method_rankings in data['baselines'].items():
                                full_method_name = f"Paper_{method_name}"
                                rankings_data[scenario_name][full_method_name] = method_rankings
                                logger.info(f"Loaded {full_method_name} with {len(method_rankings)} rankings")
                                
                except Exception as e:
                    logger.error(f"Error loading {json_file}: {e}")
                    continue
        
        # Handle NP1/NP2 split scenarios
        if 'NP1_NP2' in rankings_data:
            np_data = rankings_data['NP1_NP2']
            
            # Create separate NP1 and NP2 entries
            rankings_data['NP1'] = {}
            rankings_data['NP2'] = {}
            
            for method_name, method_rankings in np_data.items():
                if 'NP1' in method_name:
                    clean_method_name = method_name.replace('_NP1', '').replace('NP1_', '')
                    rankings_data['NP1'][clean_method_name] = method_rankings
                elif 'NP2' in method_name:
                    clean_method_name = method_name.replace('_NP2', '').replace('NP2_', '')
                    rankings_data['NP2'][clean_method_name] = method_rankings
                else:
                    # Method applies to both scenarios
                    rankings_data['NP1'][method_name] = method_rankings
                    rankings_data['NP2'][method_name] = method_rankings
            
            # Remove the combined entry
            del rankings_data['NP1_NP2']
                
        return rankings_data
    
    def calculate_ranking_consistency(self, rankings_data: Dict[str, Dict[str, Any]], 
                                    method: str = 'PatchRank') -> Dict[str, float]:
        """
        Calculate ranking stability/consistency across different scenarios
        
        Args:
            rankings_data: Rankings data from load_rankings_from_baselines()
            method: Method to analyze consistency for
            
        Returns:
            Dictionary with consistency metrics
        """
        consistency_metrics = {}
        
        # Get method rankings for all scenarios that have this method
        method_rankings = {}
        for scenario, methods in rankings_data.items():
            if method in methods and len(methods[method]) > 0:
                # Extract CVE IDs and their ranks
                cve_ranks = {item['cve_id']: item['rank'] 
                           for item in methods[method] if 'cve_id' in item and 'rank' in item}
                method_rankings[scenario] = cve_ranks
        
        if len(method_rankings) < 2:
            logger.warning(f"Need at least 2 scenarios for consistency analysis, found {len(method_rankings)}")
            return consistency_metrics
        
        # Calculate pairwise ranking correlations
        correlations = []
        scenario_pairs = []
        
        scenarios = list(method_rankings.keys())
        for i, scenario1 in enumerate(scenarios):
            for scenario2 in scenarios[i+1:]:
                # Find common CVEs between scenarios
                common_cves = set(method_rankings[scenario1].keys()) & set(method_rankings[scenario2].keys())
                
                if len(common_cves) >= 3:  # Need at least 3 common items for correlation
                    ranks1 = [method_rankings[scenario1][cve] for cve in common_cves]
                    ranks2 = [method_rankings[scenario2][cve] for cve in common_cves]
                    
                    # Calculate Spearman correlation (rank-based)
                    corr, p_value = spearmanr(ranks1, ranks2)
                    if not np.isnan(corr):
                        correlations.append(corr)
                        scenario_pairs.append((scenario1, scenario2))
                        logger.debug(f"Ranking correlation between {scenario1} and {scenario2}: {corr:.3f} (p={p_value:.3f})")
        
        if correlations:
            consistency_metrics.update({
                'mean_correlation': np.mean(correlations),
                'std_correlation': np.std(correlations),
                'min_correlation': np.min(correlations),
                'max_correlation': np.max(correlations),
                'num_scenario_pairs': len(correlations),
                'scenario_pairs': scenario_pairs
            })
        
        return consistency_metrics
    
    def calculate_topology_differentiation_score(self, rankings_data: Dict[str, Dict[str, Any]], 
                                               method: str = 'PatchRank') -> Dict[str, float]:
        """
        Calculate how well the method differentiates between different network topologies
        Focus on NP1 vs NP2 comparison as they have different topologies
        
        Args:
            rankings_data: Rankings data 
            method: Method to analyze
            
        Returns:
            Dictionary with topology differentiation metrics
        """
        differentiation_metrics = {}
        
        # Focus on NP1 vs NP2 which have different topologies
        if 'NP1' not in rankings_data or 'NP2' not in rankings_data:
            logger.warning("NP1 and NP2 scenarios not found for topology differentiation analysis")
            return differentiation_metrics
        
        if method not in rankings_data['NP1'] or method not in rankings_data['NP2']:
            logger.warning(f"Method {method} not found in NP1 or NP2 scenarios")
            return differentiation_metrics
        
        np1_rankings = rankings_data['NP1'][method]
        np2_rankings = rankings_data['NP2'][method]
        
        # Extract CVE IDs and priority scores/ranks
        np1_cve_scores = {item['cve_id']: float(item.get('priority_score', item.get('rank', 0))) 
                         for item in np1_rankings if 'cve_id' in item}
        np2_cve_scores = {item['cve_id']: float(item.get('priority_score', item.get('rank', 0))) 
                         for item in np2_rankings if 'cve_id' in item}
        
        # Find common CVEs
        common_cves = set(np1_cve_scores.keys()) & set(np2_cve_scores.keys())
        
        if len(common_cves) == 0:
            logger.warning("No common CVEs found between NP1 and NP2")
            return differentiation_metrics
        
        # Calculate topology differentiation metrics
        np1_scores = [np1_cve_scores[cve] for cve in common_cves]
        np2_scores = [np2_cve_scores[cve] for cve in common_cves]
        
        # 1. Ranking dissimilarity (1 - correlation)
        correlation, _ = spearmanr(np1_scores, np2_scores)
        if not np.isnan(correlation):
            differentiation_metrics['ranking_dissimilarity'] = 1 - abs(correlation)
        
        # 2. Score variance ratio (how much scores differ)
        score_differences = np.array(np1_scores) - np.array(np2_scores)
        differentiation_metrics.update({
            'mean_score_difference': np.mean(np.abs(score_differences)),
            'max_score_difference': np.max(np.abs(score_differences)),
            'score_difference_std': np.std(score_differences),
            'significant_differences': np.sum(np.abs(score_differences) > np.std(score_differences))
        })
        
        # 3. Top-k ranking differences
        for k in [5, 10]:
            if len(common_cves) >= k:
                # Get top-k CVEs from each scenario
                top_k_np1 = set(sorted(common_cves, key=lambda x: np1_cve_scores[x], reverse=True)[:k])
                top_k_np2 = set(sorted(common_cves, key=lambda x: np2_cve_scores[x], reverse=True)[:k])
                
                # Calculate Jaccard distance (1 - intersection/union)
                intersection = len(top_k_np1 & top_k_np2)
                union = len(top_k_np1 | top_k_np2)
                jaccard_distance = 1 - (intersection / union if union > 0 else 0)
                
                differentiation_metrics[f'top_{k}_jaccard_distance'] = jaccard_distance
                differentiation_metrics[f'top_{k}_overlap'] = intersection
        
        # 4. VPN vulnerability analysis (CVE-2019-11510 should differ significantly)
        vpn_cve = 'CVE-2019-11510'
        if vpn_cve in common_cves:
            np1_vpn_score = np1_cve_scores[vpn_cve]
            np2_vpn_score = np2_cve_scores[vpn_cve]
            vpn_score_diff = abs(np1_vpn_score - np2_vpn_score)
            
            differentiation_metrics.update({
                'vpn_vulnerability_difference': vpn_score_diff,
                'vpn_np1_score': np1_vpn_score,
                'vpn_np2_score': np2_vpn_score,
                'vpn_relative_difference': vpn_score_diff / max(np1_vpn_score, np2_vpn_score, 1e-6)
            })
        
        differentiation_metrics['total_common_cves'] = len(common_cves)
        
        return differentiation_metrics
    
    def calculate_risk_reduction_coherence(self, rankings_data: Dict[str, Dict[str, Any]], 
                                         method: str = 'PatchRank') -> Dict[str, float]:
        """
        Validate that higher-ranked patches yield higher risk reduction
        
        Args:
            rankings_data: Rankings data
            method: Method to analyze
            
        Returns:
            Dictionary with risk coherence metrics
        """
        coherence_metrics = {}
        
        for scenario, methods in rankings_data.items():
            if method not in methods:
                continue
                
            rankings = methods[method]
            
            # Extract ranks and priority scores
            ranks = []
            priority_scores = []
            
            for item in rankings:
                if 'rank' in item and 'priority_score' in item:
                    try:
                        rank = int(item['rank'])
                        score = float(item['priority_score'])
                        ranks.append(rank)
                        priority_scores.append(score)
                    except (ValueError, TypeError):
                        continue
            
            if len(ranks) >= 3:
                # Calculate correlation between rank and priority score
                # Lower ranks should have higher priority scores
                rank_score_corr, p_value = spearmanr(ranks, priority_scores)
                
                # We expect negative correlation (lower rank = higher score)
                coherence_metrics[f'{scenario}_rank_score_correlation'] = -rank_score_corr if not np.isnan(rank_score_corr) else 0
                coherence_metrics[f'{scenario}_correlation_p_value'] = p_value if not np.isnan(p_value) else 1.0
                
                # Calculate how well top-k items have higher scores than bottom-k
                if len(ranks) >= 10:
                    k = min(5, len(ranks) // 3)
                    top_k_indices = np.argsort(ranks)[:k]  # Lowest rank numbers
                    bottom_k_indices = np.argsort(ranks)[-k:]  # Highest rank numbers
                    
                    top_k_scores = [priority_scores[i] for i in top_k_indices]
                    bottom_k_scores = [priority_scores[i] for i in bottom_k_indices]
                    
                    coherence_metrics[f'{scenario}_top_{k}_mean_score'] = np.mean(top_k_scores)
                    coherence_metrics[f'{scenario}_bottom_{k}_mean_score'] = np.mean(bottom_k_scores)
                    coherence_metrics[f'{scenario}_score_separation'] = np.mean(top_k_scores) - np.mean(bottom_k_scores)
        
        return coherence_metrics
    
    def calculate_baseline_comparative_analysis(self, rankings_data: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
        """
        Compare PatchRank against baseline methods (CVSS, EPSS, etc.)
        
        Args:
            rankings_data: Rankings data with multiple methods
            
        Returns:
            Dictionary with comparative analysis results
        """
        comparative_results = {}
        
        for scenario, methods in rankings_data.items():
            if 'PatchRank' not in methods:
                continue
                
            scenario_results = {}
            
            # Get PatchRank rankings
            patchrank_rankings = {item['cve_id']: item['rank'] 
                                for item in methods['PatchRank'] if 'cve_id' in item and 'rank' in item}
            
            # Compare with all available baseline methods
            for baseline_method in methods.keys():
                if baseline_method == 'PatchRank' or baseline_method == 'metadata':
                    continue
                    
                baseline_rankings = {item['cve_id']: item['rank'] 
                                   for item in methods[baseline_method] if 'cve_id' in item and 'rank' in item}
                
                # Find common CVEs
                common_cves = set(patchrank_rankings.keys()) & set(baseline_rankings.keys())
                
                if len(common_cves) >= 3:
                    patchrank_ranks = [patchrank_rankings[cve] for cve in common_cves]
                    baseline_ranks = [baseline_rankings[cve] for cve in common_cves]
                    
                    # Calculate ranking correlations
                    spearman_corr, spearman_p = spearmanr(patchrank_ranks, baseline_ranks)
                    kendall_corr, kendall_p = kendalltau(patchrank_ranks, baseline_ranks)
                    
                    scenario_results[f'{baseline_method}_spearman_correlation'] = spearman_corr if not np.isnan(spearman_corr) else 0
                    scenario_results[f'{baseline_method}_kendall_tau'] = kendall_corr if not np.isnan(kendall_corr) else 0
                    scenario_results[f'{baseline_method}_spearman_p_value'] = spearman_p if not np.isnan(spearman_p) else 1.0
                    scenario_results[f'{baseline_method}_kendall_p_value'] = kendall_p if not np.isnan(kendall_p) else 1.0
                    
                    # Calculate ranking dissimilarity (1 - |correlation|)
                    scenario_results[f'{baseline_method}_ranking_dissimilarity'] = 1 - abs(spearman_corr) if not np.isnan(spearman_corr) else 1
                    
                    # Top-k overlap analysis
                    for k in [5, 10]:
                        if len(common_cves) >= k:
                            top_k_patchrank = set(sorted(common_cves, key=lambda x: patchrank_rankings[x])[:k])
                            top_k_baseline = set(sorted(common_cves, key=lambda x: baseline_rankings[x])[:k])
                            
                            overlap = len(top_k_patchrank & top_k_baseline)
                            scenario_results[f'{baseline_method}_top_{k}_overlap'] = overlap
                            scenario_results[f'{baseline_method}_top_{k}_overlap_ratio'] = overlap / k
            
            comparative_results[scenario] = scenario_results
        
        return comparative_results
    
    def calculate_critical_asset_prioritization(self, rankings_data: Dict[str, Dict[str, Any]],
                                              method: str = 'PatchRank') -> Dict[str, float]:
        """
        Analyze how well the method prioritizes vulnerabilities on critical assets
        
        Args:
            rankings_data: Rankings data
            method: Method to analyze
            
        Returns:
            Dictionary with critical asset prioritization metrics
        """
        prioritization_metrics = {}
        
        # Define critical assets for each scenario based on topology/business criticality
        critical_asset_mapping = {
            'NP1': ['6'],  # Domain Controller (highest business criticality)
            'NP2': ['6'],  # Domain Controller
            'ICS': ['4', '5', '6', '7'],  # Industrial control systems
            'ES': ['4', '6'],  # SQL Server, Nagios (critical services)
            'openPLC': ['default_asset']  # Single asset scenario
        }
        
        for scenario, methods in rankings_data.items():
            if method not in methods or scenario not in critical_asset_mapping:
                continue
                
            critical_assets = set(critical_asset_mapping[scenario])
            rankings = methods[method]
            
            # Separate vulnerabilities by asset criticality
            critical_asset_vulns = []
            non_critical_asset_vulns = []
            
            for item in rankings:
                asset_id = str(item.get('asset_id', ''))
                rank = item.get('rank', float('inf'))
                
                if asset_id in critical_assets:
                    critical_asset_vulns.append(rank)
                else:
                    non_critical_asset_vulns.append(rank)
            
            if critical_asset_vulns and non_critical_asset_vulns:
                # Calculate metrics
                mean_critical_rank = np.mean(critical_asset_vulns)
                mean_non_critical_rank = np.mean(non_critical_asset_vulns)
                
                prioritization_metrics.update({
                    f'{scenario}_critical_mean_rank': mean_critical_rank,
                    f'{scenario}_non_critical_mean_rank': mean_non_critical_rank,
                    f'{scenario}_rank_difference': mean_non_critical_rank - mean_critical_rank,
                    f'{scenario}_critical_asset_vulns_count': len(critical_asset_vulns),
                    f'{scenario}_non_critical_asset_vulns_count': len(non_critical_asset_vulns)
                })
                
                # Top-k analysis
                total_vulns = len(rankings)
                for k in [5, 10]:
                    if total_vulns >= k:
                        top_k_vulns = [item for item in rankings if item.get('rank', float('inf')) <= k]
                        critical_in_top_k = sum(1 for item in top_k_vulns 
                                              if str(item.get('asset_id', '')) in critical_assets)
                        
                        prioritization_metrics[f'{scenario}_critical_in_top_{k}'] = critical_in_top_k
                        prioritization_metrics[f'{scenario}_critical_ratio_top_{k}'] = critical_in_top_k / k
        
        return prioritization_metrics
    
    def generate_comprehensive_evaluation_report(self, rankings_data: Dict[str, Dict[str, Any]] = None,
                                               output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a comprehensive evaluation report using all topology-aware metrics
        
        Args:
            rankings_data: Rankings data (will load if not provided)
            output_path: Path to save report
            
        Returns:
            Comprehensive evaluation report
        """
        if rankings_data is None:
            rankings_data = self.load_rankings_from_baselines()
        
        logger.info("Generating comprehensive topology-aware evaluation report")
        
        report = {
            'metadata': {
                'evaluation_timestamp': pd.Timestamp.now().isoformat(),
                'scenarios_analyzed': list(rankings_data.keys()),
                'total_scenarios': len(rankings_data),
                'evaluation_type': 'topology_aware_without_ground_truth'
            },
            'metrics': {}
        }
        
        # 1. Ranking Consistency Analysis
        logger.info("Calculating ranking consistency metrics...")
        consistency = self.calculate_ranking_consistency(rankings_data, 'PatchRank')
        report['metrics']['ranking_consistency'] = consistency
        
        # 2. Topology Differentiation Analysis
        logger.info("Calculating topology differentiation metrics...")
        topology_diff = self.calculate_topology_differentiation_score(rankings_data, 'PatchRank')
        report['metrics']['topology_differentiation'] = topology_diff
        
        # 3. Risk Reduction Coherence Analysis
        logger.info("Calculating risk reduction coherence metrics...")
        risk_coherence = self.calculate_risk_reduction_coherence(rankings_data, 'PatchRank')
        report['metrics']['risk_reduction_coherence'] = risk_coherence
        
        # 4. Baseline Comparative Analysis
        logger.info("Calculating baseline comparative metrics...")
        baseline_comparison = self.calculate_baseline_comparative_analysis(rankings_data)
        report['metrics']['baseline_comparison'] = baseline_comparison
        
        # 5. Critical Asset Prioritization Analysis
        logger.info("Calculating critical asset prioritization metrics...")
        critical_prioritization = self.calculate_critical_asset_prioritization(rankings_data, 'PatchRank')
        report['metrics']['critical_asset_prioritization'] = critical_prioritization
        
        # 6. Enhanced nDCG Analysis (using CVSS as relevance)
        logger.info("Calculating enhanced nDCG metrics...")
        ndcg_results = {}
        for scenario, methods in rankings_data.items():
            if 'PatchRank' in methods:
                ndcg_analysis = calculate_comprehensive_ndcg_analysis(
                    {method: rankings for method, rankings in methods.items()},
                    relevance_key='cvss'
                )
                ndcg_results[scenario] = ndcg_analysis
        report['metrics']['enhanced_ndcg_analysis'] = ndcg_results
        
        # 7. Extended Top-K Analysis
        logger.info("Calculating extended Top-K analysis...")
        extended_topk_results = {}
        for scenario, methods in rankings_data.items():
            if 'PatchRank' in methods:
                scenario_topk = {}
                patchrank_rankings = methods['PatchRank']
                
                for method_name, method_rankings in methods.items():
                    if method_name != 'PatchRank':
                        topk_analysis = calculate_extended_top_k_analysis(
                            patchrank_rankings, method_rankings,
                            k_values=[5, 10, 20],
                            method1_name='PatchRank',
                            method2_name=method_name
                        )
                        scenario_topk[method_name] = topk_analysis
                
                extended_topk_results[scenario] = scenario_topk
        
        report['metrics']['extended_topk_analysis'] = extended_topk_results
        
        # 8. Summary and Key Findings  
        report['summary'] = self._generate_evaluation_summary(report['metrics'])
        
        # Save report if path provided
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"Evaluation report saved to {output_path}")
        
        return report
    
    def _generate_evaluation_summary(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of key findings from all metrics"""
        summary = {
            'key_findings': [],
            'strengths': [],
            'areas_for_improvement': [],
            'quantitative_summary': {}
        }
        
        # Topology Differentiation Assessment
        if 'topology_differentiation' in metrics:
            topo_metrics = metrics['topology_differentiation']
            
            vpn_diff = topo_metrics.get('vpn_vulnerability_difference', 0)
            ranking_dissimilarity = topo_metrics.get('ranking_dissimilarity', 0)
            
            if vpn_diff > 0.1:  # Threshold for meaningful difference
                summary['strengths'].append(f"Strong topology awareness: VPN vulnerability shows {vpn_diff:.3f} score difference between NP1 and NP2")
            
            if ranking_dissimilarity > 0.3:
                summary['strengths'].append(f"Good topology differentiation: {ranking_dissimilarity:.3f} ranking dissimilarity between different topologies")
            else:
                summary['areas_for_improvement'].append(f"Limited topology differentiation: only {ranking_dissimilarity:.3f} ranking dissimilarity")
        
        # Risk Coherence Assessment  
        if 'risk_reduction_coherence' in metrics:
            coherence_metrics = metrics['risk_reduction_coherence']
            correlations = [v for k, v in coherence_metrics.items() if 'correlation' in k and 'p_value' not in k]
            
            if correlations:
                mean_coherence = np.mean(correlations)
                if mean_coherence > 0.7:
                    summary['strengths'].append(f"Strong risk reduction coherence: {mean_coherence:.3f} average correlation")
                elif mean_coherence > 0.5:
                    summary['key_findings'].append(f"Moderate risk reduction coherence: {mean_coherence:.3f} average correlation")
                else:
                    summary['areas_for_improvement'].append(f"Weak risk reduction coherence: {mean_coherence:.3f} average correlation")
        
        # Baseline Comparison Assessment
        if 'baseline_comparison' in metrics:
            baseline_metrics = metrics['baseline_comparison']
            dissimilarities = []
            
            for scenario_data in baseline_metrics.values():
                for k, v in scenario_data.items():
                    if 'ranking_dissimilarity' in k:
                        dissimilarities.append(v)
            
            if dissimilarities:
                mean_dissimilarity = np.mean(dissimilarities)
                summary['quantitative_summary']['mean_baseline_dissimilarity'] = mean_dissimilarity
                
                if mean_dissimilarity > 0.3:
                    summary['strengths'].append(f"Meaningful differentiation from baselines: {mean_dissimilarity:.3f} average dissimilarity")
                else:
                    summary['areas_for_improvement'].append(f"Limited differentiation from baselines: {mean_dissimilarity:.3f} average dissimilarity")
        
        # Overall Assessment
        if len(summary['strengths']) >= len(summary['areas_for_improvement']):
            summary['overall_assessment'] = "PatchRank demonstrates strong topology-aware vulnerability prioritization"
        else:
            summary['overall_assessment'] = "PatchRank shows promise but requires further tuning for optimal topology awareness"
        
        return summary


def run_topology_aware_evaluation(baseline_path: str = "data/baselines",
                                output_path: str = "results/topology_aware_evaluation_report.json") -> Dict[str, Any]:
    """
    Convenience function to run complete topology-aware evaluation
    
    Args:
        baseline_path: Path to baselines directory
        output_path: Path to save evaluation report
        
    Returns:
        Comprehensive evaluation report
    """
    evaluator = TopologyAwareMetrics()
    evaluator.baseline_data_path = Path(baseline_path)
    
    logger.info("Starting topology-aware evaluation without ground truth...")
    
    # Load rankings data
    rankings_data = evaluator.load_rankings_from_baselines()
    
    if not rankings_data:
        raise ValueError(f"No ranking data found in {baseline_path}")
    
    # Generate comprehensive report
    report = evaluator.generate_comprehensive_evaluation_report(rankings_data, output_path)
    
    logger.info(f"Topology-aware evaluation complete. Report saved to {output_path}")
    
    return report