"""
Multi-Scenario Evaluation Framework for PatchRank
Implements scenario-appropriate evaluation strategies based on vulnerability overlap and domain characteristics
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple, Optional
import logging
from pathlib import Path
from dataclasses import dataclass

from .statistical_utils import calculate_enhanced_correlation_analysis, batch_correlation_analysis
from .evaluation_metrics import calculate_comprehensive_ndcg_analysis, calculate_ranking_quality_metrics
from .data_validation import generate_compatibility_matrix

logger = logging.getLogger(__name__)


@dataclass
class ScenarioCluster:
    """Define scenario clusters for domain-specific analysis"""
    name: str
    scenarios: List[str]
    characteristics: List[str]
    evaluation_focus: str


class MultiScenarioEvaluator:
    """
    Comprehensive multi-scenario evaluation framework
    Uses scenario-appropriate evaluation strategies
    """
    
    def __init__(self):
        """Initialize multi-scenario evaluator"""
        # Define scenario clusters
        self.scenario_clusters = {
            'network_enterprise': ScenarioCluster(
                name='Network & Enterprise Systems',
                scenarios=['NP1', 'NP2', 'ES'],
                characteristics=[
                    'Network-based vulnerabilities',
                    'Multiple networked assets', 
                    'Topology-dependent risks',
                    'Enterprise-scale deployment'
                ],
                evaluation_focus='Network topology awareness and enterprise prioritization'
            ),
            'industrial_control': ScenarioCluster(
                name='Industrial Control & IoT',
                scenarios=['ICS', 'openPLC'],
                characteristics=[
                    'Operational Technology (OT)',
                    'Safety-critical systems',
                    'Limited network exposure',
                    'Physical process impact'
                ],
                evaluation_focus='Critical asset prioritization and safety considerations'
            )
        }
        
        # Topology comparison pairs (scenarios with shared CVEs)
        self.topology_pairs = [('NP1', 'NP2')]  # Main topology comparison
        
        # Baseline methods for comparison
        self.baseline_methods = ['CVSS_Base', 'EPSS', 'CVSS_BE']
    
    def analyze_scenario_characteristics(self, rankings_data: Dict[str, Dict[str, List[Dict[str, Any]]]]) -> Dict[str, Any]:
        """
        Analyze characteristics of each scenario for evaluation planning
        """
        scenario_analysis = {}
        
        for scenario, methods in rankings_data.items():
            if 'PatchRank' in methods:
                patchrank_rankings = methods['PatchRank']
                
                # Basic statistics
                cve_count = len(patchrank_rankings)
                cve_ids = [item['cve_id'] for item in patchrank_rankings if 'cve_id' in item]
                
                # Score distribution analysis
                scores = [float(item.get('priority_score', 0)) for item in patchrank_rankings 
                         if 'priority_score' in item]
                
                # Asset diversity
                asset_ids = set(str(item.get('asset_id', '')) for item in patchrank_rankings
                              if 'asset_id' in item)
                
                # CVSS severity distribution
                cvss_scores = [float(item.get('cvss', 0)) for item in patchrank_rankings
                             if 'cvss' in item]
                
                scenario_analysis[scenario] = {
                    'vulnerability_count': cve_count,
                    'asset_count': len(asset_ids),
                    'score_statistics': {
                        'mean': np.mean(scores) if scores else 0,
                        'std': np.std(scores) if scores else 0,
                        'range': (np.min(scores), np.max(scores)) if scores else (0, 0)
                    },
                    'cvss_distribution': {
                        'mean': np.mean(cvss_scores) if cvss_scores else 0,
                        'critical_count': sum(1 for s in cvss_scores if s >= 9.0),
                        'high_count': sum(1 for s in cvss_scores if 7.0 <= s < 9.0),
                        'medium_count': sum(1 for s in cvss_scores if 4.0 <= s < 7.0)
                    },
                    'available_baselines': [method for method in methods.keys() if method != 'PatchRank']
                }
        
        return scenario_analysis
    
    def evaluate_topology_awareness(self, rankings_data: Dict[str, Dict[str, List[Dict[str, Any]]]]) -> Dict[str, Any]:
        """
        Comprehensive topology awareness evaluation using NP1/NP2 comparison
        """
        logger.info("Evaluating topology awareness using NP1/NP2 comparison...")
        
        topology_results = {}
        
        for scenario1, scenario2 in self.topology_pairs:
            if scenario1 not in rankings_data or scenario2 not in rankings_data:
                continue
            
            if 'PatchRank' not in rankings_data[scenario1] or 'PatchRank' not in rankings_data[scenario2]:
                continue
            
            rankings1 = rankings_data[scenario1]['PatchRank']
            rankings2 = rankings_data[scenario2]['PatchRank']
            
            # Extract rankings for comparison
            ranks1_dict = {item['cve_id']: float(item.get('priority_score', 0)) 
                          for item in rankings1 if 'cve_id' in item}
            ranks2_dict = {item['cve_id']: float(item.get('priority_score', 0))
                          for item in rankings2 if 'cve_id' in item}
            
            # Find common CVEs
            common_cves = set(ranks1_dict.keys()) & set(ranks2_dict.keys())
            
            if len(common_cves) >= 3:
                scores1 = [ranks1_dict[cve] for cve in common_cves]
                scores2 = [ranks2_dict[cve] for cve in common_cves]
                
                # Enhanced correlation analysis
                enhanced_analysis = calculate_enhanced_correlation_analysis(scores1, scores2)
                
                # Topology-specific metrics
                topology_metrics = self._calculate_topology_specific_metrics(
                    rankings1, rankings2, common_cves
                )
                
                pair_key = f"{scenario1}_vs_{scenario2}"
                topology_results[pair_key] = {
                    'common_vulnerabilities': len(common_cves),
                    'enhanced_correlation': enhanced_analysis,
                    'topology_metrics': topology_metrics,
                    'interpretation': self._interpret_topology_results(enhanced_analysis, topology_metrics)
                }
        
        return topology_results
    
    def evaluate_method_generalizability(self, rankings_data: Dict[str, Dict[str, List[Dict[str, Any]]]]) -> Dict[str, Any]:
        """
        Evaluate PatchRank generalizability across different vulnerability contexts
        """
        logger.info("Evaluating method generalizability across scenarios...")
        
        generalizability_results = {}
        
        # Scenario-by-scenario analysis
        for scenario, methods in rankings_data.items():
            if 'PatchRank' not in methods:
                continue
            
            patchrank_rankings = methods['PatchRank']
            
            # Ranking quality metrics
            quality_metrics = calculate_ranking_quality_metrics(patchrank_rankings)
            
            # Baseline comparison within scenario
            scenario_baselines = {}
            for baseline in self.baseline_methods:
                if baseline in methods:
                    # Compare PatchRank vs this baseline
                    baseline_rankings = methods[baseline]
                    
                    # Extract scores for comparison
                    patchrank_scores = [float(item.get('priority_score', 0)) 
                                      for item in patchrank_rankings if 'cve_id' in item]
                    baseline_scores = [float(item.get('priority_score', item.get('rank', 0))) 
                                     for item in baseline_rankings if 'cve_id' in item]
                    
                    if len(patchrank_scores) == len(baseline_scores) and len(patchrank_scores) >= 3:
                        comparison = calculate_enhanced_correlation_analysis(patchrank_scores, baseline_scores)
                        scenario_baselines[baseline] = comparison
            
            generalizability_results[scenario] = {
                'ranking_quality': quality_metrics,
                'baseline_comparisons': scenario_baselines,
                'domain_adaptation_score': self._calculate_domain_adaptation_score(quality_metrics, scenario_baselines)
            }
        
        # Cross-cluster analysis
        cluster_results = {}
        for cluster_name, cluster in self.scenario_clusters.items():
            cluster_scenarios = [s for s in cluster.scenarios if s in generalizability_results]
            if len(cluster_scenarios) >= 2:
                cluster_results[cluster_name] = self._analyze_cluster_consistency(
                    cluster_scenarios, generalizability_results
                )
        
        generalizability_results['cluster_analysis'] = cluster_results
        
        return generalizability_results
    
    def evaluate_domain_specific_performance(self, rankings_data: Dict[str, Dict[str, List[Dict[str, Any]]]]) -> Dict[str, Any]:
        """
        Domain-specific performance evaluation by scenario clusters
        """
        logger.info("Evaluating domain-specific performance...")
        
        domain_results = {}
        
        for cluster_name, cluster in self.scenario_clusters.items():
            cluster_scenarios = [s for s in cluster.scenarios if s in rankings_data]
            
            if not cluster_scenarios:
                continue
            
            # Collect cluster data
            cluster_data = {}
            for scenario in cluster_scenarios:
                if 'PatchRank' in rankings_data[scenario]:
                    cluster_data[scenario] = rankings_data[scenario]
            
            if cluster_data:
                # Domain-specific nDCG analysis - flatten data for each scenario
                ndcg_analysis = {}
                for scenario, methods in cluster_data.items():
                    scenario_ndcg = calculate_comprehensive_ndcg_analysis(
                        methods, relevance_key='cvss'
                    )
                    ndcg_analysis[scenario] = scenario_ndcg
                
                # Domain-specific characteristics
                domain_characteristics = self._analyze_domain_characteristics(
                    cluster_data, cluster.characteristics
                )
                
                domain_results[cluster_name] = {
                    'cluster_info': cluster,
                    'scenarios_analyzed': cluster_scenarios,
                    'ndcg_analysis': ndcg_analysis,
                    'domain_characteristics': domain_characteristics,
                    'performance_summary': self._summarize_domain_performance(ndcg_analysis, domain_characteristics)
                }
        
        return domain_results
    
    def _calculate_topology_specific_metrics(self, rankings1: List[Dict], rankings2: List[Dict], 
                                           common_cves: set) -> Dict[str, Any]:
        """Calculate topology-specific differentiation metrics"""
        metrics = {}
        
        # VPN vulnerability analysis (if present)
        vpn_cve = 'CVE-2019-11510'
        if vpn_cve in common_cves:
            vpn1 = [item for item in rankings1 if item.get('cve_id') == vpn_cve]
            vpn2 = [item for item in rankings2 if item.get('cve_id') == vpn_cve]
            
            if vpn1 and vpn2:
                vpn1_score = float(vpn1[0].get('priority_score', 0))
                vpn2_score = float(vpn2[0].get('priority_score', 0))
                vpn_diff = abs(vpn1_score - vpn2_score)
                
                metrics['vpn_analysis'] = {
                    'score_difference': vpn_diff,
                    'relative_difference': vpn_diff / max(vpn1_score, vpn2_score, 1e-6),
                    'interpretation': 'Strong topology awareness' if vpn_diff > 0.3 else 'Moderate topology awareness'
                }
        
        # Top-K ranking differences
        for k in [5, 10]:
            if len(common_cves) >= k:
                rank1_dict = {item['cve_id']: int(item.get('rank', 999)) for item in rankings1}
                rank2_dict = {item['cve_id']: int(item.get('rank', 999)) for item in rankings2}
                
                top_k1 = set(sorted(common_cves, key=lambda x: rank1_dict.get(x, 999))[:k])
                top_k2 = set(sorted(common_cves, key=lambda x: rank2_dict.get(x, 999))[:k])
                
                overlap = len(top_k1 & top_k2)
                jaccard = overlap / len(top_k1 | top_k2) if len(top_k1 | top_k2) > 0 else 0
                
                metrics[f'top_{k}_analysis'] = {
                    'overlap_count': overlap,
                    'overlap_ratio': overlap / k,
                    'jaccard_similarity': jaccard
                }
        
        return metrics
    
    def _calculate_domain_adaptation_score(self, quality_metrics: Dict, baseline_comparisons: Dict) -> float:
        """Calculate how well the method adapts to the specific domain"""
        score = 0.0
        
        # Quality component (30%)
        if quality_metrics:
            monotonicity = quality_metrics.get('monotonicity_score', 0)
            discriminative = quality_metrics.get('discriminative_power', 0)
            quality_component = (monotonicity + discriminative) / 2
            score += 0.3 * quality_component
        
        # Baseline differentiation component (70%)
        if baseline_comparisons:
            dissimilarities = []
            for baseline, comparison in baseline_comparisons.items():
                if 'spearman' in comparison:
                    corr = abs(comparison['spearman'].get('correlation', 0))
                    dissimilarity = 1 - corr
                    dissimilarities.append(dissimilarity)
            
            if dissimilarities:
                mean_dissimilarity = np.mean(dissimilarities)
                score += 0.7 * mean_dissimilarity
        
        return score
    
    def _analyze_cluster_consistency(self, scenarios: List[str], results: Dict) -> Dict[str, Any]:
        """Analyze consistency within scenario cluster"""
        quality_scores = []
        adaptation_scores = []
        
        for scenario in scenarios:
            if scenario in results:
                quality = results[scenario].get('ranking_quality', {})
                if quality.get('monotonicity_score'):
                    quality_scores.append(quality['monotonicity_score'])
                
                adaptation = results[scenario].get('domain_adaptation_score', 0)
                if adaptation > 0:
                    adaptation_scores.append(adaptation)
        
        return {
            'scenarios': scenarios,
            'quality_consistency': {
                'mean': np.mean(quality_scores) if quality_scores else 0,
                'std': np.std(quality_scores) if quality_scores else 0,
                'scores': quality_scores
            },
            'adaptation_consistency': {
                'mean': np.mean(adaptation_scores) if adaptation_scores else 0,
                'std': np.std(adaptation_scores) if adaptation_scores else 0,
                'scores': adaptation_scores
            }
        }
    
    def _analyze_domain_characteristics(self, cluster_data: Dict, characteristics: List[str]) -> Dict[str, Any]:
        """Analyze domain-specific characteristics"""
        analysis = {
            'characteristics': characteristics,
            'evidence': {}
        }
        
        # Critical asset prioritization (for industrial control cluster)
        if 'Critical asset prioritization' in characteristics or 'safety-critical systems' in characteristics:
            # Check if critical assets get higher priority
            critical_evidence = []
            for scenario, methods in cluster_data.items():
                if 'PatchRank' in methods:
                    rankings = methods['PatchRank']
                    # Look for high CVSS scores in top ranks
                    top_5 = sorted(rankings, key=lambda x: int(x.get('rank', 999)))[:5]
                    high_cvss_in_top5 = sum(1 for item in top_5 if float(item.get('cvss', 0)) >= 8.0)
                    critical_evidence.append(high_cvss_in_top5 / 5)  # Ratio
            
            analysis['evidence']['critical_asset_focus'] = {
                'mean_high_severity_in_top5': np.mean(critical_evidence) if critical_evidence else 0,
                'interpretation': 'Strong' if np.mean(critical_evidence or [0]) > 0.6 else 'Moderate'
            }
        
        # Network topology awareness (for network/enterprise cluster)  
        if 'Network-based vulnerabilities' in characteristics:
            # Evidence already captured in topology analysis
            analysis['evidence']['network_topology_awareness'] = {
                'note': 'See topology_awareness evaluation results',
                'primary_evidence': 'VPN vulnerability differentiation in NP1/NP2 comparison'
            }
        
        return analysis
    
    def _summarize_domain_performance(self, ndcg_analysis: Dict, characteristics: Dict) -> Dict[str, Any]:
        """Summarize performance within domain"""
        summary = {}
        
        # nDCG performance summary
        if 'method_results' in ndcg_analysis:
            patchrank_scores = []
            for scenario, methods in ndcg_analysis['method_results'].items():
                if 'PatchRank' in methods:
                    ndcg5 = methods['PatchRank'].get('ndcg_at_5', 0)
                    ndcg10 = methods['PatchRank'].get('ndcg_at_10', 0)
                    patchrank_scores.append((ndcg5, ndcg10))
            
            if patchrank_scores:
                mean_ndcg5 = np.mean([s[0] for s in patchrank_scores])
                mean_ndcg10 = np.mean([s[1] for s in patchrank_scores])
                
                summary['ndcg_performance'] = {
                    'mean_ndcg_at_5': mean_ndcg5,
                    'mean_ndcg_at_10': mean_ndcg10,
                    'performance_level': 'Excellent' if mean_ndcg5 > 0.9 else 'Good' if mean_ndcg5 > 0.7 else 'Moderate'
                }
        
        # Domain-specific strengths
        if 'evidence' in characteristics:
            summary['domain_specific_strengths'] = characteristics['evidence']
        
        return summary
    
    def _interpret_topology_results(self, enhanced_analysis: Dict, topology_metrics: Dict) -> str:
        """Interpret topology awareness results"""
        spearman_corr = enhanced_analysis.get('spearman', {}).get('correlation', 0)
        vpn_analysis = topology_metrics.get('vpn_analysis', {})
        
        if vpn_analysis.get('score_difference', 0) > 0.3:
            if abs(spearman_corr) < 0.7:
                return "Strong topology awareness with meaningful ranking differentiation"
            else:
                return "Moderate topology awareness - some differentiation but high correlation"
        else:
            return "Limited topology awareness detected"
    
    def generate_multi_scenario_report(self, rankings_data: Dict[str, Dict[str, List[Dict[str, Any]]]]) -> Dict[str, Any]:
        """
        Generate comprehensive multi-scenario evaluation report
        """
        logger.info("Generating comprehensive multi-scenario evaluation report...")
        
        # Run all analyses
        scenario_characteristics = self.analyze_scenario_characteristics(rankings_data)
        compatibility_analysis = generate_compatibility_matrix(rankings_data)
        topology_evaluation = self.evaluate_topology_awareness(rankings_data)
        generalizability_evaluation = self.evaluate_method_generalizability(rankings_data)
        domain_evaluation = self.evaluate_domain_specific_performance(rankings_data)
        
        # Compile comprehensive report
        report = {
            'metadata': {
                'evaluation_type': 'multi_scenario_comprehensive',
                'scenarios_analyzed': list(rankings_data.keys()),
                'scenario_clusters': {name: cluster.scenarios for name, cluster in self.scenario_clusters.items()},
                'evaluation_strategy': 'Scenario-appropriate evaluation leveraging domain characteristics'
            },
            'scenario_characteristics': scenario_characteristics,
            'scenario_compatibility': compatibility_analysis,
            'topology_awareness': topology_evaluation,
            'method_generalizability': generalizability_evaluation,
            'domain_specific_performance': domain_evaluation,
            'executive_summary': self._generate_executive_summary(
                topology_evaluation, generalizability_evaluation, domain_evaluation, compatibility_analysis
            )
        }
        
        return report
    
    def _generate_executive_summary(self, topology_results: Dict, generalizability_results: Dict, 
                                  domain_results: Dict, compatibility_results: Dict) -> Dict[str, Any]:
        """Generate executive summary of multi-scenario evaluation"""
        summary = {
            'key_findings': [],
            'evidence_strength': {},
            'academic_contributions': [],
            'methodology_validation': [],
            'scenario_compatibility_insights': [],
            'evaluation_limitations': []
        }
        
        # Topology awareness evidence
        for pair_key, results in topology_results.items():
            if 'vpn_analysis' in results['topology_metrics']:
                vpn_diff = results['topology_metrics']['vpn_analysis']['score_difference']
                if vpn_diff > 0.3:
                    summary['key_findings'].append(
                        f"Strong topology awareness: {vpn_diff:.3f} VPN vulnerability score difference in {pair_key}"
                    )
                    summary['evidence_strength']['topology_awareness'] = 'Strong'
        
        # Generalizability evidence
        adaptation_scores = []
        for scenario, results in generalizability_results.items():
            if scenario != 'cluster_analysis' and 'domain_adaptation_score' in results:
                adaptation_scores.append(results['domain_adaptation_score'])
        
        if adaptation_scores:
            mean_adaptation = np.mean(adaptation_scores)
            summary['key_findings'].append(
                f"Method generalizability: {mean_adaptation:.3f} average domain adaptation score across {len(adaptation_scores)} scenarios"
            )
            summary['evidence_strength']['generalizability'] = 'Strong' if mean_adaptation > 0.5 else 'Moderate'
        
        # Domain-specific evidence
        for domain, results in domain_results.items():
            if 'performance_summary' in results and 'ndcg_performance' in results['performance_summary']:
                ndcg_perf = results['performance_summary']['ndcg_performance']
                perf_level = ndcg_perf.get('performance_level', 'Unknown')
                summary['key_findings'].append(
                    f"{domain}: {perf_level} performance (nDCG@5: {ndcg_perf.get('mean_ndcg_at_5', 0):.3f})"
                )
        
        # Scenario compatibility insights
        if 'summary' in compatibility_results:
            comp_summary = compatibility_results['summary']
            total_pairs = comp_summary.get('total_unique_pairs', 0)
            comparable_pairs = comp_summary.get('comparable_pairs', 0)
            
            if total_pairs > 0:
                comparability_ratio = comparable_pairs / total_pairs
                if comparability_ratio < 0.3:
                    summary['scenario_compatibility_insights'].append(
                        f"Limited cross-scenario comparability: {comparable_pairs}/{total_pairs} pairs comparable"
                    )
                    summary['evaluation_limitations'].append(
                        "Different vulnerability sets across scenarios limit direct cross-scenario correlation analysis"
                    )
                elif comparability_ratio > 0.7:
                    summary['scenario_compatibility_insights'].append(
                        f"High cross-scenario comparability: {comparable_pairs}/{total_pairs} pairs comparable"
                    )
                else:
                    summary['scenario_compatibility_insights'].append(
                        f"Moderate cross-scenario comparability: {comparable_pairs}/{total_pairs} pairs comparable"
                    )
            
            # Add specific recommendations from compatibility analysis
            if 'recommendations' in comp_summary:
                summary['methodology_validation'].extend(comp_summary['recommendations'])
        
        # Academic contributions
        summary['academic_contributions'] = [
            "Multi-scenario evaluation framework without ground truth requirements",
            "Domain-specific performance validation across diverse vulnerability contexts", 
            "Topology-aware prioritization with controlled comparison methodology",
            "Scenario-appropriate evaluation strategy respecting domain characteristics"
        ]
        
        # Overall assessment
        strong_evidence_count = sum(1 for v in summary['evidence_strength'].values() if v == 'Strong')
        if strong_evidence_count >= 2:
            summary['overall_assessment'] = "Strong evidence supporting PatchRank effectiveness across multiple scenarios and domains"
        elif strong_evidence_count >= 1:
            summary['overall_assessment'] = "Moderate evidence supporting PatchRank with domain-specific strengths"
        else:
            summary['overall_assessment'] = "Limited evidence - method shows promise but requires further validation"
        
        return summary


def run_multi_scenario_evaluation(rankings_data: Dict[str, Dict[str, List[Dict[str, Any]]]] = None,
                                baseline_path: str = "data/baselines",
                                output_path: str = "evaluation/results/multi_scenario_analysis.json") -> Dict[str, Any]:
    """
    Run comprehensive multi-scenario evaluation
    """
    evaluator = MultiScenarioEvaluator()
    
    if rankings_data is None:
        # Load rankings data
        from .topology_aware_metrics import TopologyAwareMetrics
        from pathlib import Path
        
        topo_evaluator = TopologyAwareMetrics()
        topo_evaluator.baseline_data_path = Path(baseline_path)
        rankings_data = topo_evaluator.load_rankings_from_baselines()
    
    # Generate comprehensive report
    report = evaluator.generate_multi_scenario_report(rankings_data)
    
    # Save report
    if output_path:
        import json
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"Multi-scenario evaluation report saved to {output_path}")
    
    return report