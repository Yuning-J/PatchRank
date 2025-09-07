"""
Statistical Utility Functions for Enhanced PatchRank Evaluation
Implements bootstrap confidence intervals, multiple comparison corrections, and effect sizes
"""

import numpy as np
import pandas as pd
from typing import List, Tuple, Dict, Any, Optional
from scipy import stats
from scipy.stats import spearmanr, kendalltau
import logging
import warnings
warnings.filterwarnings('ignore', category=RuntimeWarning)

logger = logging.getLogger(__name__)


def bootstrap_spearman_ci(rank1: List[float], rank2: List[float], 
                         n_bootstrap: int = 1000, ci: float = 0.95) -> Tuple[float, float, float]:
    """
    Calculate bootstrap confidence interval for Spearman correlation
    
    Args:
        rank1: First ranking data
        rank2: Second ranking data  
        n_bootstrap: Number of bootstrap samples
        ci: Confidence interval level (0-1)
        
    Returns:
        Tuple of (correlation, lower_ci, upper_ci)
    """
    if len(rank1) != len(rank2) or len(rank1) < 3:
        return 0.0, 0.0, 0.0
    
    try:
        # Original correlation
        original_corr, _ = spearmanr(rank1, rank2)
        if np.isnan(original_corr):
            return 0.0, 0.0, 0.0
        
        # Bootstrap sampling
        n_samples = len(rank1)
        bootstrap_corrs = []
        
        for _ in range(n_bootstrap):
            # Resample with replacement
            indices = np.random.choice(n_samples, n_samples, replace=True)
            boot_rank1 = [rank1[i] for i in indices]
            boot_rank2 = [rank2[i] for i in indices]
            
            # Calculate correlation for bootstrap sample
            boot_corr, _ = spearmanr(boot_rank1, boot_rank2)
            if not np.isnan(boot_corr):
                bootstrap_corrs.append(boot_corr)
        
        if not bootstrap_corrs:
            return original_corr, original_corr, original_corr
        
        # Calculate confidence interval
        alpha = 1 - ci
        lower_percentile = (alpha / 2) * 100
        upper_percentile = (1 - alpha / 2) * 100
        
        lower_ci = np.percentile(bootstrap_corrs, lower_percentile)
        upper_ci = np.percentile(bootstrap_corrs, upper_percentile)
        
        return original_corr, lower_ci, upper_ci
        
    except Exception as e:
        logger.error(f"Bootstrap confidence interval calculation failed: {e}")
        return 0.0, 0.0, 0.0


def bootstrap_kendall_ci(rank1: List[float], rank2: List[float],
                        n_bootstrap: int = 1000, ci: float = 0.95) -> Tuple[float, float, float]:
    """
    Calculate bootstrap confidence interval for Kendall's tau
    
    Args:
        rank1: First ranking data
        rank2: Second ranking data
        n_bootstrap: Number of bootstrap samples  
        ci: Confidence interval level (0-1)
        
    Returns:
        Tuple of (tau, lower_ci, upper_ci)
    """
    if len(rank1) != len(rank2) or len(rank1) < 3:
        return 0.0, 0.0, 0.0
    
    try:
        # Original correlation
        original_tau, _ = kendalltau(rank1, rank2)
        if np.isnan(original_tau):
            return 0.0, 0.0, 0.0
        
        # Bootstrap sampling
        n_samples = len(rank1)
        bootstrap_taus = []
        
        for _ in range(n_bootstrap):
            # Resample with replacement
            indices = np.random.choice(n_samples, n_samples, replace=True)
            boot_rank1 = [rank1[i] for i in indices]
            boot_rank2 = [rank2[i] for i in indices]
            
            # Calculate tau for bootstrap sample
            boot_tau, _ = kendalltau(boot_rank1, boot_rank2)
            if not np.isnan(boot_tau):
                bootstrap_taus.append(boot_tau)
        
        if not bootstrap_taus:
            return original_tau, original_tau, original_tau
            
        # Calculate confidence interval
        alpha = 1 - ci
        lower_percentile = (alpha / 2) * 100
        upper_percentile = (1 - alpha / 2) * 100
        
        lower_ci = np.percentile(bootstrap_taus, lower_percentile)
        upper_ci = np.percentile(bootstrap_taus, upper_percentile)
        
        return original_tau, lower_ci, upper_ci
        
    except Exception as e:
        logger.error(f"Bootstrap Kendall CI calculation failed: {e}")
        return 0.0, 0.0, 0.0


def bonferroni_correction(p_values: List[float], alpha: float = 0.05) -> Tuple[List[bool], List[float]]:
    """
    Apply Bonferroni correction for multiple comparisons
    
    Args:
        p_values: List of p-values to correct
        alpha: Family-wise error rate
        
    Returns:
        Tuple of (significant_list, corrected_p_values)
    """
    n_comparisons = len(p_values)
    if n_comparisons == 0:
        return [], []
    
    # Bonferroni correction
    corrected_alpha = alpha / n_comparisons
    corrected_p_values = [min(p * n_comparisons, 1.0) for p in p_values]
    significant = [p < corrected_alpha for p in p_values]
    
    return significant, corrected_p_values


def holm_bonferroni_correction(p_values: List[float], alpha: float = 0.05) -> Tuple[List[bool], List[float]]:
    """
    Apply Holm-Bonferroni correction (less conservative than Bonferroni)
    
    Args:
        p_values: List of p-values to correct
        alpha: Family-wise error rate
        
    Returns:
        Tuple of (significant_list, corrected_p_values)
    """
    n_comparisons = len(p_values)
    if n_comparisons == 0:
        return [], []
    
    # Create pairs of (p_value, original_index)
    indexed_p_values = [(p, i) for i, p in enumerate(p_values)]
    
    # Sort by p-value
    indexed_p_values.sort(key=lambda x: x[0])
    
    # Apply Holm procedure
    significant = [False] * n_comparisons
    corrected_p_values = [0.0] * n_comparisons
    
    for rank, (p_value, original_index) in enumerate(indexed_p_values):
        # Holm correction factor
        correction_factor = n_comparisons - rank
        corrected_p = min(p_value * correction_factor, 1.0)
        corrected_p_values[original_index] = corrected_p
        
        # Test significance
        adjusted_alpha = alpha / correction_factor
        if p_value <= adjusted_alpha:
            significant[original_index] = True
        else:
            # Once we fail to reject, all remaining tests are non-significant
            break
    
    return significant, corrected_p_values


def cohens_d(sample1: List[float], sample2: List[float]) -> float:
    """
    Calculate Cohen's d effect size
    
    Args:
        sample1: First sample
        sample2: Second sample
        
    Returns:
        Cohen's d effect size
    """
    if len(sample1) < 2 or len(sample2) < 2:
        return 0.0
    
    try:
        # Calculate means
        mean1 = np.mean(sample1)
        mean2 = np.mean(sample2)
        
        # Calculate pooled standard deviation
        var1 = np.var(sample1, ddof=1)
        var2 = np.var(sample2, ddof=1)
        n1, n2 = len(sample1), len(sample2)
        
        pooled_std = np.sqrt(((n1 - 1) * var1 + (n2 - 1) * var2) / (n1 + n2 - 2))
        
        if pooled_std == 0:
            return 0.0
        
        # Cohen's d
        d = (mean1 - mean2) / pooled_std
        return d
        
    except Exception as e:
        logger.error(f"Cohen's d calculation failed: {e}")
        return 0.0


def cliffs_delta(sample1: List[float], sample2: List[float]) -> float:
    """
    Calculate Cliff's Delta (non-parametric effect size)
    
    Args:
        sample1: First sample
        sample2: Second sample
        
    Returns:
        Cliff's Delta effect size (-1 to 1)
    """
    if len(sample1) == 0 or len(sample2) == 0:
        return 0.0
    
    try:
        # Count dominance relationships
        dominance_count = 0
        total_comparisons = 0
        
        for x1 in sample1:
            for x2 in sample2:
                total_comparisons += 1
                if x1 > x2:
                    dominance_count += 1
                elif x1 < x2:
                    dominance_count -= 1
                # Equal values contribute 0
        
        if total_comparisons == 0:
            return 0.0
        
        # Cliff's delta
        delta = dominance_count / total_comparisons
        return delta
        
    except Exception as e:
        logger.error(f"Cliff's delta calculation failed: {e}")
        return 0.0


def interpret_effect_size(effect_size: float, method: str = "cohens_d") -> str:
    """
    Provide interpretation of effect size magnitude
    
    Args:
        effect_size: Calculated effect size
        method: Method used ("cohens_d" or "cliffs_delta")
        
    Returns:
        String interpretation of effect size
    """
    abs_effect = abs(effect_size)
    
    if method == "cohens_d":
        if abs_effect < 0.2:
            return f"Negligible (d = {effect_size:.3f})"
        elif abs_effect < 0.5:
            return f"Small (d = {effect_size:.3f})"
        elif abs_effect < 0.8:
            return f"Medium (d = {effect_size:.3f})"
        else:
            return f"Large (d = {effect_size:.3f})"
    
    elif method == "cliffs_delta":
        if abs_effect < 0.147:
            return f"Negligible (δ = {effect_size:.3f})"
        elif abs_effect < 0.33:
            return f"Small (δ = {effect_size:.3f})"
        elif abs_effect < 0.474:
            return f"Medium (δ = {effect_size:.3f})"
        else:
            return f"Large (δ = {effect_size:.3f})"
    
    return f"Unknown method: {effect_size:.3f}"


def calculate_enhanced_correlation_analysis(rank1: List[float], rank2: List[float],
                                          n_bootstrap: int = 1000, alpha: float = 0.05) -> Dict[str, Any]:
    """
    Complete enhanced correlation analysis with CI and effect sizes
    
    Args:
        rank1: First ranking data
        rank2: Second ranking data
        n_bootstrap: Number of bootstrap samples
        alpha: Significance level
        
    Returns:
        Dictionary with enhanced correlation results
    """
    if len(rank1) != len(rank2) or len(rank1) < 3:
        return {
            'error': 'Insufficient data for correlation analysis',
            'sample_size': len(rank1)
        }
    
    results = {
        'sample_size': len(rank1),
        'alpha': alpha,
        'n_bootstrap': n_bootstrap
    }
    
    # Spearman correlation with bootstrap CI
    spearman_corr, spearman_lower, spearman_upper = bootstrap_spearman_ci(
        rank1, rank2, n_bootstrap, 1 - alpha
    )
    
    results['spearman'] = {
        'correlation': spearman_corr,
        'ci_lower': spearman_lower,
        'ci_upper': spearman_upper,
        'ci_width': spearman_upper - spearman_lower,
        'significant': not (spearman_lower <= 0 <= spearman_upper)  # CI doesn't contain 0
    }
    
    # Kendall tau with bootstrap CI
    kendall_tau, kendall_lower, kendall_upper = bootstrap_kendall_ci(
        rank1, rank2, n_bootstrap, 1 - alpha
    )
    
    results['kendall'] = {
        'tau': kendall_tau,
        'ci_lower': kendall_lower,
        'ci_upper': kendall_upper,
        'ci_width': kendall_upper - kendall_lower,
        'significant': not (kendall_lower <= 0 <= kendall_upper)
    }
    
    # Effect sizes
    cohens_d_value = cohens_d(rank1, rank2)
    cliffs_delta_value = cliffs_delta(rank1, rank2)
    
    results['effect_sizes'] = {
        'cohens_d': {
            'value': cohens_d_value,
            'interpretation': interpret_effect_size(cohens_d_value, "cohens_d")
        },
        'cliffs_delta': {
            'value': cliffs_delta_value,
            'interpretation': interpret_effect_size(cliffs_delta_value, "cliffs_delta")
        }
    }
    
    return results


def apply_multiple_comparison_corrections(correlation_results: List[Dict[str, Any]], 
                                        alpha: float = 0.05) -> Dict[str, Any]:
    """
    Apply multiple comparison corrections to a list of correlation results
    
    Args:
        correlation_results: List of correlation analysis results
        alpha: Family-wise error rate
        
    Returns:
        Dictionary with corrected results
    """
    if not correlation_results:
        return {'error': 'No correlation results provided'}
    
    # Extract p-values (using significance from CI for bootstrap)
    raw_significant = []
    comparison_names = []
    
    for i, result in enumerate(correlation_results):
        if 'spearman' in result:
            raw_significant.append(result['spearman'].get('significant', False))
            comparison_names.append(f"comparison_{i}")
    
    if not raw_significant:
        return {'error': 'No valid significance tests found'}
    
    # Convert boolean significance to approximate p-values for correction
    # This is a limitation of using CI-based significance
    approx_p_values = [0.01 if sig else 0.10 for sig in raw_significant]
    
    # Apply corrections
    bonferroni_sig, bonferroni_p = bonferroni_correction(approx_p_values, alpha)
    holm_sig, holm_p = holm_bonferroni_correction(approx_p_values, alpha)
    
    correction_results = {
        'n_comparisons': len(raw_significant),
        'family_wise_alpha': alpha,
        'bonferroni': {
            'adjusted_alpha': alpha / len(raw_significant),
            'significant_comparisons': sum(bonferroni_sig),
            'results': [
                {
                    'comparison': name,
                    'original_significant': orig_sig,
                    'bonferroni_significant': bon_sig,
                    'bonferroni_p': bon_p
                }
                for name, orig_sig, bon_sig, bon_p 
                in zip(comparison_names, raw_significant, bonferroni_sig, bonferroni_p)
            ]
        },
        'holm_bonferroni': {
            'significant_comparisons': sum(holm_sig),
            'results': [
                {
                    'comparison': name,
                    'original_significant': orig_sig,
                    'holm_significant': holm_sig,
                    'holm_p': holm_p
                }
                for name, orig_sig, holm_sig, holm_p
                in zip(comparison_names, raw_significant, holm_sig, holm_p)
            ]
        }
    }
    
    return correction_results


# Convenience functions for common use cases

def enhanced_spearman_analysis(rank1: List[float], rank2: List[float]) -> Dict[str, Any]:
    """Quick enhanced Spearman analysis with all improvements"""
    return calculate_enhanced_correlation_analysis(rank1, rank2)


def batch_correlation_analysis(ranking_data: Dict[str, List[float]], 
                             baseline_key: str = "PatchRank") -> Dict[str, Any]:
    """
    Perform enhanced correlation analysis across multiple ranking methods
    
    Args:
        ranking_data: Dictionary of {method_name: ranking_list}
        baseline_key: Reference method for comparisons
        
    Returns:
        Dictionary with batch analysis results and multiple comparison corrections
    """
    if baseline_key not in ranking_data:
        return {'error': f'Baseline method {baseline_key} not found'}
    
    baseline_ranks = ranking_data[baseline_key]
    correlation_results = []
    
    # Analyze each method against baseline
    for method_name, method_ranks in ranking_data.items():
        if method_name == baseline_key:
            continue
        
        if len(method_ranks) == len(baseline_ranks):
            result = calculate_enhanced_correlation_analysis(baseline_ranks, method_ranks)
            result['method_comparison'] = f"{baseline_key}_vs_{method_name}"
            correlation_results.append(result)
    
    # Apply multiple comparison corrections
    corrections = apply_multiple_comparison_corrections(correlation_results)
    
    return {
        'baseline_method': baseline_key,
        'correlation_analyses': correlation_results,
        'multiple_comparison_corrections': corrections,
        'summary': {
            'total_comparisons': len(correlation_results),
            'methods_analyzed': list(ranking_data.keys())
        }
    }