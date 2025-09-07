"""
Enhanced Evaluation Metrics for PatchRank
Implements nDCG, extended Top-K analysis, and advanced ranking metrics
"""

import numpy as np
import pandas as pd
from typing import List, Dict, Any, Tuple, Optional, Union
import logging
from collections import defaultdict
import math

logger = logging.getLogger(__name__)


def calculate_ndcg(rankings: List[Dict[str, Any]], 
                  relevance_scores: Dict[str, float],
                  k: int = 10) -> float:
    """
    Calculate Normalized Discounted Cumulative Gain (nDCG)
    
    Args:
        rankings: List of ranking items with 'cve_id' and 'rank'
        relevance_scores: Dictionary mapping CVE IDs to relevance scores (e.g., CVSS)
        k: Number of top items to consider
        
    Returns:
        nDCG@k score (0-1, higher is better)
    """
    if not rankings or not relevance_scores:
        return 0.0
    
    try:
        # Sort rankings by rank (ascending)
        sorted_rankings = sorted(rankings, key=lambda x: int(x.get('rank', float('inf'))))
        
        # Calculate DCG@k
        dcg = 0.0
        for i, item in enumerate(sorted_rankings[:k]):
            cve_id = item.get('cve_id', '')
            if cve_id in relevance_scores:
                relevance = relevance_scores[cve_id]
                # DCG formula: rel_i / log2(i + 2) where i is 0-indexed
                dcg += relevance / math.log2(i + 2)
        
        # Calculate IDCG@k (ideal ranking by relevance scores)
        # Get relevance scores for available CVEs
        available_relevances = []
        for item in sorted_rankings:
            cve_id = item.get('cve_id', '')
            if cve_id in relevance_scores:
                available_relevances.append(relevance_scores[cve_id])
        
        # Sort relevances in descending order for ideal ranking
        ideal_relevances = sorted(available_relevances, reverse=True)[:k]
        
        idcg = 0.0
        for i, relevance in enumerate(ideal_relevances):
            idcg += relevance / math.log2(i + 2)
        
        # Calculate nDCG
        if idcg == 0:
            return 0.0
        
        ndcg = dcg / idcg
        return min(ndcg, 1.0)  # Cap at 1.0
        
    except Exception as e:
        logger.error(f"nDCG calculation failed: {e}")
        return 0.0


def calculate_extended_top_k_analysis(rankings1: List[Dict[str, Any]], 
                                     rankings2: List[Dict[str, Any]],
                                     k_values: List[int] = [5, 10, 20],
                                     method1_name: str = "Method1",
                                     method2_name: str = "Method2") -> Dict[str, Any]:
    """
    Extended Top-K overlap analysis for multiple K values
    
    Args:
        rankings1: First method's rankings
        rankings2: Second method's rankings
        k_values: List of K values to analyze
        method1_name: Name of first method
        method2_name: Name of second method
        
    Returns:
        Dictionary with Top-K analysis results
    """
    if not rankings1 or not rankings2:
        return {'error': 'Empty rankings provided'}
    
    # Convert rankings to dictionaries {cve_id: rank}
    ranks1 = {item['cve_id']: int(item['rank']) for item in rankings1 if 'cve_id' in item and 'rank' in item}
    ranks2 = {item['cve_id']: int(item['rank']) for item in rankings2 if 'cve_id' in item and 'rank' in item}
    
    # Find common CVEs
    common_cves = set(ranks1.keys()) & set(ranks2.keys())
    
    if len(common_cves) == 0:
        return {'error': 'No common CVEs between rankings'}
    
    results = {
        'method1': method1_name,
        'method2': method2_name,
        'total_common_cves': len(common_cves),
        'k_analyses': {}
    }
    
    for k in k_values:
        if k > len(common_cves):
            continue
        
        # Get Top-K CVEs from each ranking
        top_k_1 = set(sorted(common_cves, key=lambda x: ranks1[x])[:k])
        top_k_2 = set(sorted(common_cves, key=lambda x: ranks2[x])[:k])
        
        # Calculate overlap metrics
        intersection = top_k_1 & top_k_2
        union = top_k_1 | top_k_2
        
        overlap_count = len(intersection)
        overlap_ratio = overlap_count / k
        jaccard_index = len(intersection) / len(union) if union else 0
        
        # Calculate weighted overlap (higher positions get more weight)
        weighted_overlap = 0.0
        for cve in intersection:
            rank1_pos = sorted(list(common_cves), key=lambda x: ranks1[x]).index(cve) + 1
            rank2_pos = sorted(list(common_cves), key=lambda x: ranks2[x]).index(cve) + 1
            
            if rank1_pos <= k and rank2_pos <= k:
                # Weight decreases with position (position 1 gets weight 1.0, position k gets weight 1/k)
                weight = 2 / (rank1_pos + rank2_pos)  # Harmonic mean weighting
                weighted_overlap += weight
        
        # Normalize weighted overlap
        max_weighted_overlap = sum(2 / (2 * i) for i in range(1, k + 1))  # If all top-k match perfectly
        weighted_overlap_normalized = weighted_overlap / max_weighted_overlap if max_weighted_overlap > 0 else 0
        
        # Rank-based distance (average absolute difference in ranks for top-k items)
        rank_distances = []
        for cve in intersection:
            dist = abs(ranks1[cve] - ranks2[cve])
            rank_distances.append(dist)
        
        avg_rank_distance = np.mean(rank_distances) if rank_distances else 0
        
        results['k_analyses'][k] = {
            'top_k_overlap_count': overlap_count,
            'top_k_overlap_ratio': overlap_ratio,
            'jaccard_index': jaccard_index,
            'weighted_overlap_normalized': weighted_overlap_normalized,
            'average_rank_distance': avg_rank_distance,
            'method1_top_k': sorted(list(top_k_1)),
            'method2_top_k': sorted(list(top_k_2)),
            'common_top_k': sorted(list(intersection))
        }
    
    return results


def calculate_rank_based_precision_recall(rankings: List[Dict[str, Any]],
                                         ground_truth_top_k: List[str],
                                         k: int = 10) -> Dict[str, float]:
    """
    Calculate precision and recall at rank k
    (Useful when we have some ground truth or reference ranking)
    
    Args:
        rankings: Method's rankings
        ground_truth_top_k: List of CVE IDs that should be in top-k
        k: Rank cutoff
        
    Returns:
        Dictionary with precision, recall, and F1 score
    """
    if not rankings or not ground_truth_top_k:
        return {'precision': 0.0, 'recall': 0.0, 'f1': 0.0}
    
    try:
        # Get top-k from rankings
        sorted_rankings = sorted(rankings, key=lambda x: int(x.get('rank', float('inf'))))
        predicted_top_k = [item['cve_id'] for item in sorted_rankings[:k] if 'cve_id' in item]
        
        # Calculate precision and recall
        true_positives = len(set(predicted_top_k) & set(ground_truth_top_k))
        
        precision = true_positives / len(predicted_top_k) if predicted_top_k else 0.0
        recall = true_positives / len(ground_truth_top_k) if ground_truth_top_k else 0.0
        
        # F1 score
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'true_positives': true_positives,
            'predicted_k': len(predicted_top_k),
            'ground_truth_k': len(ground_truth_top_k)
        }
        
    except Exception as e:
        logger.error(f"Precision-recall calculation failed: {e}")
        return {'precision': 0.0, 'recall': 0.0, 'f1': 0.0}


def calculate_ranking_quality_metrics(rankings: List[Dict[str, Any]],
                                     score_key: str = 'priority_score') -> Dict[str, float]:
    """
    Calculate various ranking quality metrics
    
    Args:
        rankings: List of ranking items
        score_key: Key for the ranking score
        
    Returns:
        Dictionary with ranking quality metrics
    """
    if not rankings:
        return {}
    
    try:
        # Extract ranks and scores
        items_with_data = []
        for item in rankings:
            if 'rank' in item and score_key in item:
                try:
                    rank = int(item['rank'])
                    score = float(item[score_key])
                    items_with_data.append((rank, score))
                except (ValueError, TypeError):
                    continue
        
        if len(items_with_data) < 2:
            return {}
        
        ranks, scores = zip(*items_with_data)
        ranks = list(ranks)
        scores = list(scores)
        
        # 1. Rank-Score Correlation (should be negative - lower ranks have higher scores)
        rank_score_corr = np.corrcoef(ranks, scores)[0, 1] if len(ranks) > 1 else 0
        
        # 2. Monotonicity measure (how well scores decrease with increasing rank)
        monotonicity_violations = 0
        total_pairs = 0
        for i in range(len(ranks)):
            for j in range(i + 1, len(ranks)):
                total_pairs += 1
                # If rank_i < rank_j, then score_i should >= score_j
                if ranks[i] < ranks[j] and scores[i] < scores[j]:
                    monotonicity_violations += 1
                elif ranks[i] > ranks[j] and scores[i] > scores[j]:
                    monotonicity_violations += 1
        
        monotonicity_score = 1 - (monotonicity_violations / total_pairs) if total_pairs > 0 else 1.0
        
        # 3. Score spread metrics
        score_range = max(scores) - min(scores)
        score_std = np.std(scores)
        score_cv = score_std / np.mean(scores) if np.mean(scores) != 0 else 0  # Coefficient of variation
        
        # 4. Ranking discriminative power (how well it separates items)
        # Calculate number of unique scores vs total items
        unique_scores = len(set(scores))
        discriminative_power = unique_scores / len(scores)
        
        return {
            'rank_score_correlation': rank_score_corr,
            'monotonicity_score': monotonicity_score,
            'score_range': score_range,
            'score_std': score_std,
            'score_coefficient_variation': score_cv,
            'discriminative_power': discriminative_power,
            'total_items': len(rankings),
            'items_with_scores': len(items_with_data)
        }
        
    except Exception as e:
        logger.error(f"Ranking quality metrics calculation failed: {e}")
        return {}


def calculate_comprehensive_ndcg_analysis(rankings_data: Dict[str, List[Dict[str, Any]]],
                                        relevance_key: str = 'cvss',
                                        k_values: List[int] = [5, 10, 20]) -> Dict[str, Any]:
    """
    Comprehensive nDCG analysis across multiple methods and k values
    
    Args:
        rankings_data: Dictionary mapping method names to rankings
        relevance_key: Key to use for relevance scores (e.g., 'cvss', 'epss')
        k_values: List of k values for nDCG@k calculation
        
    Returns:
        Dictionary with comprehensive nDCG analysis
    """
    results = {
        'relevance_key': relevance_key,
        'k_values': k_values,
        'method_results': {},
        'summary': {}
    }
    
    # Extract relevance scores from all methods
    all_relevance_scores = {}
    for method_name, rankings in rankings_data.items():
        for item in rankings:
            cve_id = item.get('cve_id', '')
            if cve_id and relevance_key in item:
                try:
                    score = float(item[relevance_key])
                    all_relevance_scores[cve_id] = score
                except (ValueError, TypeError):
                    continue
    
    if not all_relevance_scores:
        results['error'] = f'No valid {relevance_key} scores found'
        return results
    
    # Calculate nDCG for each method and k value
    for method_name, rankings in rankings_data.items():
        method_results = {}
        
        for k in k_values:
            ndcg_score = calculate_ndcg(rankings, all_relevance_scores, k)
            method_results[f'ndcg_at_{k}'] = ndcg_score
        
        results['method_results'][method_name] = method_results
    
    # Generate summary statistics
    summary_stats = {}
    for k in k_values:
        k_key = f'ndcg_at_{k}'
        k_scores = [method_results.get(k_key, 0) 
                   for method_results in results['method_results'].values()]
        
        if k_scores:
            summary_stats[k_key] = {
                'mean': np.mean(k_scores),
                'std': np.std(k_scores),
                'min': np.min(k_scores),
                'max': np.max(k_scores),
                'best_method': max(results['method_results'].items(), 
                                 key=lambda x: x[1].get(k_key, 0))[0]
            }
    
    results['summary'] = summary_stats
    results['total_cves_with_relevance'] = len(all_relevance_scores)
    
    return results


def calculate_ranking_stability_variance(rankings_data: Dict[str, List[Dict[str, Any]]],
                                       method_name: str = "PatchRank") -> Dict[str, float]:
    """
    Calculate ranking stability variance across scenarios
    
    Args:
        rankings_data: Dictionary mapping scenario names to rankings
        method_name: Method to analyze
        
    Returns:
        Dictionary with stability variance metrics
    """
    if len(rankings_data) < 2:
        return {'error': 'Need at least 2 scenarios for stability analysis'}
    
    try:
        # Extract rankings for common CVEs across all scenarios
        scenario_rankings = {}
        all_cves = set()
        
        for scenario, rankings in rankings_data.items():
            scenario_cves = {}
            for item in rankings:
                if 'cve_id' in item and 'rank' in item:
                    cve_id = item['cve_id']
                    rank = int(item['rank'])
                    scenario_cves[cve_id] = rank
                    all_cves.add(cve_id)
            scenario_rankings[scenario] = scenario_cves
        
        # Find CVEs present in all scenarios
        common_cves = all_cves.copy()
        for scenario_cves in scenario_rankings.values():
            common_cves &= set(scenario_cves.keys())
        
        if len(common_cves) < 3:
            return {'error': 'Insufficient common CVEs for stability analysis'}
        
        # Calculate rank variance for each CVE across scenarios
        cve_variances = []
        for cve in common_cves:
            ranks = [scenario_rankings[scenario][cve] for scenario in scenario_rankings]
            rank_variance = np.var(ranks)
            cve_variances.append(rank_variance)
        
        # Stability metrics
        mean_variance = np.mean(cve_variances)
        std_variance = np.std(cve_variances)
        max_variance = np.max(cve_variances)
        stability_score = 1 / (1 + mean_variance)  # Higher score = more stable
        
        # Calculate percentage of CVEs with high stability (low variance)
        low_variance_threshold = np.percentile(cve_variances, 25)
        stable_cves_ratio = sum(1 for var in cve_variances if var <= low_variance_threshold) / len(cve_variances)
        
        return {
            'mean_rank_variance': mean_variance,
            'std_rank_variance': std_variance,
            'max_rank_variance': max_variance,
            'stability_score': stability_score,
            'stable_cves_ratio': stable_cves_ratio,
            'total_common_cves': len(common_cves),
            'scenarios_analyzed': len(scenario_rankings)
        }
        
    except Exception as e:
        logger.error(f"Ranking stability variance calculation failed: {e}")
        return {'error': str(e)}


def generate_enhanced_metrics_report(rankings_data: Dict[str, Dict[str, List[Dict[str, Any]]]],
                                   relevance_key: str = 'cvss') -> Dict[str, Any]:
    """
    Generate comprehensive enhanced metrics report
    
    Args:
        rankings_data: Nested dictionary {scenario: {method: rankings}}
        relevance_key: Key for relevance scores
        
    Returns:
        Comprehensive enhanced metrics report
    """
    report = {
        'metadata': {
            'evaluation_type': 'enhanced_metrics_analysis',
            'relevance_key': relevance_key,
            'scenarios': list(rankings_data.keys())
        },
        'analyses': {}
    }
    
    # 1. nDCG Analysis per scenario
    logger.info("Calculating nDCG analysis...")
    ndcg_results = {}
    for scenario, methods in rankings_data.items():
        ndcg_results[scenario] = calculate_comprehensive_ndcg_analysis(
            methods, relevance_key
        )
    report['analyses']['ndcg_analysis'] = ndcg_results
    
    # 2. Extended Top-K Analysis
    logger.info("Calculating extended Top-K analysis...")
    topk_results = {}
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
            
            topk_results[scenario] = scenario_topk
    
    report['analyses']['extended_topk_analysis'] = topk_results
    
    # 3. Ranking Quality Metrics
    logger.info("Calculating ranking quality metrics...")
    quality_results = {}
    for scenario, methods in rankings_data.items():
        scenario_quality = {}
        for method_name, rankings in methods.items():
            quality_metrics = calculate_ranking_quality_metrics(rankings)
            scenario_quality[method_name] = quality_metrics
        quality_results[scenario] = scenario_quality
    
    report['analyses']['ranking_quality'] = quality_results
    
    # 4. Cross-scenario stability (for PatchRank)
    logger.info("Calculating ranking stability...")
    patchrank_scenarios = {scenario: methods['PatchRank'] 
                          for scenario, methods in rankings_data.items() 
                          if 'PatchRank' in methods}
    
    if len(patchrank_scenarios) > 1:
        stability_analysis = calculate_ranking_stability_variance(patchrank_scenarios)
        report['analyses']['ranking_stability'] = stability_analysis
    
    return report