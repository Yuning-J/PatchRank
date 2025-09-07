"""
Data Validation Utilities for PatchRank Evaluation
Provides comprehensive validation for ranking data structures and content
"""

import numpy as np
from typing import Dict, List, Any, Set, Tuple
import logging

logger = logging.getLogger(__name__)


def validate_ranking_data(rankings: List[Dict[str, Any]], context: str = "unknown") -> Dict[str, Any]:
    """
    Validate ranking data structure and content
    
    Args:
        rankings: List of ranking items to validate
        context: Context information for better error messages
        
    Returns:
        Dictionary with validation results
    """
    
    validation_result = {
        'valid': True,
        'errors': [],
        'warnings': [],
        'stats': {},
        'context': context
    }
    
    if not rankings:
        validation_result['valid'] = False
        validation_result['errors'].append("Empty rankings list")
        return validation_result
    
    # Check required fields
    required_fields = ['cve_id', 'rank']
    optional_fields = ['priority_score', 'cvss', 'epss', 'asset_id']
    
    for i, item in enumerate(rankings):
        if not isinstance(item, dict):
            validation_result['errors'].append(f"Item {i} is not a dictionary")
            validation_result['valid'] = False
            continue
            
        for field in required_fields:
            if field not in item:
                validation_result['errors'].append(f"Item {i} ({item.get('cve_id', 'unknown')}) missing required field: {field}")
                validation_result['valid'] = False
    
    # Check for duplicates
    cve_ids = [item.get('cve_id') for item in rankings if 'cve_id' in item]
    if len(cve_ids) != len(set(cve_ids)):
        duplicates = [cve for cve in set(cve_ids) if cve_ids.count(cve) > 1]
        validation_result['errors'].append(f"Duplicate CVE IDs found: {duplicates}")
        validation_result['valid'] = False
    
    # Check rank consistency
    ranks = [item.get('rank') for item in rankings if 'rank' in item and item.get('rank') is not None]
    if ranks:
        try:
            ranks = [int(r) for r in ranks]
            
            if min(ranks) < 1:
                validation_result['warnings'].append(f"Minimum rank is {min(ranks)}, expected >= 1")
            
            if len(set(ranks)) != len(ranks):
                duplicate_ranks = [r for r in set(ranks) if ranks.count(r) > 1]
                validation_result['errors'].append(f"Duplicate ranks found: {duplicate_ranks}")
                validation_result['valid'] = False
                
            # Check for gaps in ranking
            expected_ranks = set(range(1, len(ranks) + 1))
            actual_ranks = set(ranks)
            missing_ranks = expected_ranks - actual_ranks
            if missing_ranks:
                validation_result['warnings'].append(f"Missing ranks in sequence: {sorted(missing_ranks)}")
                
        except (ValueError, TypeError) as e:
            validation_result['errors'].append(f"Invalid rank values found: {e}")
            validation_result['valid'] = False
    
    # Validate priority scores
    priority_scores = []
    for item in rankings:
        if 'priority_score' in item:
            try:
                score = float(item['priority_score'])
                priority_scores.append(score)
            except (ValueError, TypeError):
                validation_result['warnings'].append(f"Invalid priority_score for {item.get('cve_id', 'unknown')}: {item.get('priority_score')}")
    
    # Check score-rank consistency
    if priority_scores and len(priority_scores) == len(ranks):
        # Higher priority scores should have lower ranks (closer to 1)
        score_rank_pairs = [(score, rank) for score, rank in zip(priority_scores, ranks)]
        score_rank_pairs.sort(key=lambda x: x[0], reverse=True)  # Sort by score descending
        
        expected_ranks = list(range(1, len(score_rank_pairs) + 1))
        actual_ranks = [pair[1] for pair in score_rank_pairs]
        
        rank_correlation = np.corrcoef(expected_ranks, actual_ranks)[0, 1] if len(expected_ranks) > 1 else 1.0
        if rank_correlation < 0.9:
            validation_result['warnings'].append(f"Poor score-rank correlation: {rank_correlation:.3f}")
    
    # Validate CVSS scores
    cvss_scores = []
    for item in rankings:
        if 'cvss' in item:
            try:
                cvss = float(item['cvss'])
                if not (0.0 <= cvss <= 10.0):
                    validation_result['warnings'].append(f"CVSS score out of range [0,10]: {cvss} for {item.get('cve_id')}")
                else:
                    cvss_scores.append(cvss)
            except (ValueError, TypeError):
                validation_result['warnings'].append(f"Invalid CVSS score for {item.get('cve_id')}: {item.get('cvss')}")
    
    # Validate EPSS scores
    epss_scores = []
    for item in rankings:
        if 'epss' in item:
            try:
                epss = float(item['epss'])
                if not (0.0 <= epss <= 1.0):
                    validation_result['warnings'].append(f"EPSS score out of range [0,1]: {epss} for {item.get('cve_id')}")
                else:
                    epss_scores.append(epss)
            except (ValueError, TypeError):
                validation_result['warnings'].append(f"Invalid EPSS score for {item.get('cve_id')}: {item.get('epss')}")
    
    # Compile statistics
    validation_result['stats'] = {
        'total_items': len(rankings),
        'unique_cves': len(set(cve_ids)) if cve_ids else 0,
        'rank_range': (min(ranks), max(ranks)) if ranks else (None, None),
        'priority_score_stats': {
            'count': len(priority_scores),
            'range': (min(priority_scores), max(priority_scores)) if priority_scores else (None, None),
            'mean': np.mean(priority_scores) if priority_scores else None,
            'std': np.std(priority_scores) if priority_scores else None
        },
        'cvss_stats': {
            'count': len(cvss_scores),
            'range': (min(cvss_scores), max(cvss_scores)) if cvss_scores else (None, None),
            'mean': np.mean(cvss_scores) if cvss_scores else None
        },
        'epss_stats': {
            'count': len(epss_scores),
            'range': (min(epss_scores), max(epss_scores)) if epss_scores else (None, None),
            'mean': np.mean(epss_scores) if epss_scores else None
        },
        'fields_present': {
            field: sum(1 for item in rankings if field in item and item[field] is not None)
            for field in required_fields + optional_fields
        }
    }
    
    return validation_result


def validate_scenario_data(scenario_data: Dict[str, List[Dict[str, Any]]], scenario_name: str) -> Dict[str, Any]:
    """
    Validate all ranking methods within a scenario
    
    Args:
        scenario_data: Dictionary mapping method names to rankings
        scenario_name: Name of the scenario
        
    Returns:
        Dictionary with validation results for all methods
    """
    
    scenario_validation = {
        'scenario': scenario_name,
        'valid': True,
        'method_validations': {},
        'cross_method_issues': [],
        'summary': {}
    }
    
    if not scenario_data:
        scenario_validation['valid'] = False
        scenario_validation['cross_method_issues'].append("No methods found in scenario")
        return scenario_validation
    
    # Validate each method
    for method_name, rankings in scenario_data.items():
        validation = validate_ranking_data(rankings, f"{scenario_name}.{method_name}")
        scenario_validation['method_validations'][method_name] = validation
        
        if not validation['valid']:
            scenario_validation['valid'] = False
    
    # Cross-method validation
    method_names = list(scenario_data.keys())
    if len(method_names) > 1:
        # Check CVE consistency across methods
        method_cves = {}
        for method_name, rankings in scenario_data.items():
            cve_set = {item.get('cve_id') for item in rankings if 'cve_id' in item}
            method_cves[method_name] = cve_set
        
        # Find common CVEs
        all_methods = list(method_cves.keys())
        common_cves = set.intersection(*method_cves.values()) if method_cves else set()
        
        if len(common_cves) == 0:
            scenario_validation['cross_method_issues'].append("No common CVEs across methods")
        
        # Check for significant CVE set differences
        for i, method1 in enumerate(all_methods):
            for method2 in all_methods[i+1:]:
                cves1 = method_cves[method1]
                cves2 = method_cves[method2]
                
                only_in_1 = cves1 - cves2
                only_in_2 = cves2 - cves1
                
                if len(only_in_1) > 0 or len(only_in_2) > 0:
                    scenario_validation['cross_method_issues'].append(
                        f"{method1} vs {method2}: {len(only_in_1)} unique to {method1}, {len(only_in_2)} unique to {method2}"
                    )
    
    # Generate summary statistics
    total_items = sum(len(rankings) for rankings in scenario_data.values())
    valid_methods = sum(1 for val in scenario_validation['method_validations'].values() if val['valid'])
    
    scenario_validation['summary'] = {
        'total_methods': len(method_names),
        'valid_methods': valid_methods,
        'total_rankings': total_items,
        'common_cves_across_methods': len(common_cves) if 'common_cves' in locals() else 0,
        'has_cross_method_issues': len(scenario_validation['cross_method_issues']) > 0
    }
    
    return scenario_validation


def generate_compatibility_matrix(rankings_data: Dict[str, Dict[str, List[Dict[str, Any]]]]) -> Dict[str, Any]:
    """
    Generate a compatibility matrix showing which scenarios can be meaningfully compared
    
    Args:
        rankings_data: Nested dictionary {scenario: {method: rankings}}
        
    Returns:
        Dictionary with compatibility matrix and analysis
    """
    
    scenarios = list(rankings_data.keys())
    n_scenarios = len(scenarios)
    
    # Initialize matrix
    compatibility_matrix = {}
    scenario_stats = {}
    
    # Collect scenario statistics
    for scenario in scenarios:
        if 'PatchRank' in rankings_data[scenario]:
            patchrank_data = rankings_data[scenario]['PatchRank']
            cve_set = {item.get('cve_id') for item in patchrank_data if 'cve_id' in item}
            
            scenario_stats[scenario] = {
                'cve_count': len(cve_set),
                'cve_set': cve_set
            }
        else:
            scenario_stats[scenario] = {
                'cve_count': 0,
                'cve_set': set()
            }
    
    # Build compatibility matrix
    for i, scenario1 in enumerate(scenarios):
        compatibility_matrix[scenario1] = {}
        
        for j, scenario2 in enumerate(scenarios):
            if i == j:
                # Same scenario - perfect compatibility
                compatibility_matrix[scenario1][scenario2] = {
                    'overlap_ratio': 1.0,
                    'common_cves': scenario_stats[scenario1]['cve_count'],
                    'comparable': True,
                    'reason': 'Same scenario'
                }
            else:
                # Different scenarios
                cves1 = scenario_stats[scenario1]['cve_set']
                cves2 = scenario_stats[scenario2]['cve_set']
                
                if len(cves1) == 0 or len(cves2) == 0:
                    # No PatchRank data available
                    compatibility_matrix[scenario1][scenario2] = {
                        'overlap_ratio': 0.0,
                        'common_cves': 0,
                        'comparable': False,
                        'reason': 'Missing PatchRank data'
                    }
                else:
                    common_cves = cves1 & cves2
                    overlap_ratio = len(common_cves) / min(len(cves1), len(cves2))
                    comparable = len(common_cves) >= 3
                    
                    compatibility_matrix[scenario1][scenario2] = {
                        'overlap_ratio': overlap_ratio,
                        'common_cves': len(common_cves),
                        'comparable': comparable,
                        'reason': f"{len(common_cves)} common CVEs" if comparable else "Insufficient common CVEs"
                    }
    
    # Generate summary analysis
    total_pairs = n_scenarios * (n_scenarios - 1) // 2  # Unique pairs
    comparable_pairs = 0
    high_overlap_pairs = 0  # > 50% overlap
    
    for i, scenario1 in enumerate(scenarios):
        for j, scenario2 in enumerate(scenarios[i+1:], i+1):
            comp_data = compatibility_matrix[scenario1][scenario2]
            if comp_data['comparable']:
                comparable_pairs += 1
            if comp_data['overlap_ratio'] > 0.5:
                high_overlap_pairs += 1
    
    summary = {
        'total_scenarios': n_scenarios,
        'total_unique_pairs': total_pairs,
        'comparable_pairs': comparable_pairs,
        'high_overlap_pairs': high_overlap_pairs,
        'comparability_ratio': comparable_pairs / total_pairs if total_pairs > 0 else 0.0,
        'scenario_stats': scenario_stats,
        'recommendations': []
    }
    
    # Generate recommendations
    if comparable_pairs == 0:
        summary['recommendations'].append("No scenarios are directly comparable. Focus on within-scenario analysis.")
    elif comparable_pairs < total_pairs * 0.3:
        summary['recommendations'].append("Limited cross-scenario comparability. Use scenario clustering approach.")
    else:
        summary['recommendations'].append("Good cross-scenario comparability. Standard correlation analysis applicable.")
    
    if high_overlap_pairs > 0:
        summary['recommendations'].append(f"{high_overlap_pairs} scenario pairs have >50% CVE overlap - suitable for direct comparison.")
    
    return {
        'compatibility_matrix': compatibility_matrix,
        'summary': summary
    }


def validate_evaluation_results(evaluation_results: Dict[str, Any], context: str = "evaluation") -> Dict[str, Any]:
    """
    Validate evaluation results for statistical anomalies and inconsistencies
    
    Args:
        evaluation_results: Dictionary containing evaluation results
        context: Context of the evaluation
        
    Returns:
        Dictionary with validation results and warnings
    """
    
    validation = {
        'valid': True,
        'warnings': [],
        'anomalies': [],
        'context': context
    }
    
    # Check for zero correlation anomaly
    if 'analyses' in evaluation_results and 'ranking_stability' in evaluation_results['analyses']:
        stability = evaluation_results['analyses']['ranking_stability']
        mean_corr = stability.get('mean_cross_scenario_correlation')
        
        if mean_corr is not None and abs(mean_corr) < 0.01:
            validation['anomalies'].append(
                "Near-zero cross-scenario correlation detected. This may indicate "
                "non-comparable scenarios or a calculation error."
            )
    
    # Check for perfect correlations
    if 'analyses' in evaluation_results and 'baseline_comparisons' in evaluation_results['analyses']:
        baselines = evaluation_results['analyses']['baseline_comparisons']
        
        perfect_corr_count = 0
        for scenario_data in baselines.values():
            for method_data in scenario_data.values():
                if isinstance(method_data, dict):
                    corr = method_data.get('spearman_correlation', 0)
                    if abs(abs(corr) - 1.0) < 0.001:  # Essentially perfect correlation
                        perfect_corr_count += 1
        
        if perfect_corr_count > len(baselines) * 0.5:  # More than half are perfect
            validation['warnings'].append(
                f"Unusually high number of perfect correlations ({perfect_corr_count}). "
                "This may indicate identical rankings or synthetic baseline issues."
            )
    
    # Check for missing data
    required_sections = ['metadata', 'analyses']
    for section in required_sections:
        if section not in evaluation_results:
            validation['warnings'].append(f"Missing required section: {section}")
            validation['valid'] = False
    
    # Check executive summary consistency
    if 'executive_summary' in evaluation_results:
        summary = evaluation_results['executive_summary']
        
        findings = summary.get('key_findings', [])
        evidence = summary.get('quantitative_evidence', {})
        
        if len(findings) == 0:
            validation['warnings'].append("No key findings reported in executive summary")
        
        if len(evidence) == 0:
            validation['warnings'].append("No quantitative evidence provided in executive summary")
    
    return validation