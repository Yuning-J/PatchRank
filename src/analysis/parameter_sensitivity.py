"""
Parameter Sensitivity Analysis Module
Implements comprehensive parameter sweeping and sensitivity analysis for δ, θ, η1, η2, η3
Includes variance-based sensitivity indices, statistical tests, and advanced visualizations
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Tuple, Any, Optional, Union
import json
import os
from pathlib import Path
import logging
from scipy import stats
from scipy.stats import kendalltau, spearmanr, shapiro, kurtosis, skew
import warnings
from datetime import datetime
from itertools import combinations
import statsmodels.api as sm
from statsmodels.formula.api import ols
from sklearn.preprocessing import PolynomialFeatures
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score

# Import SALib for Sobol analysis if available
try:
    from SALib.sample import saltelli
    from SALib.analyze import sobol

    SALIB_AVAILABLE = True
except ImportError:
    SALIB_AVAILABLE = False
    warnings.warn("SALib not available. Sobol indices calculation will be skipped.")

from ..conf import get_config, update_parameters, get_delta_theta
from ..core.patch_prioritizer import PatchPrioritizer
from ..core.risk_calculator import RiskCalculator
from ..core.models import Asset, System, AnalysisLevel

logger = logging.getLogger(__name__)


class ParameterSensitivityAnalyzer:
    """Comprehensive parameter sensitivity analysis for vulnerability risk ranking"""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize parameter sensitivity analyzer

        Args:
            config_path: Path to configuration file (optional)
        """
        self.config = get_config()
        self.patch_prioritizer = PatchPrioritizer()
        self.risk_calculator = RiskCalculator()

        # Create results directory with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results_dir = Path(self.config.results_dir) / "sensitivity" / timestamp
        self.results_dir.mkdir(parents=True, exist_ok=True)

        # Parameter ranges as specified
        self.parameter_ranges = {
            'delta': np.arange(0.3, 0.8, 0.1),  # δ ∈ [0.3, 0.7] step 0.1
            'theta': np.arange(0.3, 0.8, 0.1),  # θ ∈ [0.3, 0.7] step 0.1
            'eta1': np.arange(0.1, 0.6, 0.1),  # η1 ∈ [0.1, 0.5] step 0.1
            'eta2': np.arange(0.1, 0.6, 0.1),  # η2 ∈ [0.1, 0.5] step 0.1
            'eta3': np.arange(0.1, 0.6, 0.1),  # η3 ∈ [0.1, 0.5] step 0.1
        }

        # Store baseline rankings and test data
        self.baseline_rankings = None
        self.baseline_parameters = None
        self.test_data = None

        # Statistical settings
        self.confidence_level = 0.95
        self.n_bootstrap = 1000
        self.significance_level = 0.05

    def set_baseline(self, test_data: Union[Asset, System], analysis_level: str = "asset") -> None:
        """
        Set baseline rankings and parameters for comparison

        Args:
            test_data: Asset or System object for testing
            analysis_level: "asset" or "system"
        """
        self.test_data = test_data
        self.analysis_level = analysis_level

        # Store current parameters as baseline
        self.baseline_parameters = {
            'delta': get_delta_theta()[0],
            'theta': get_delta_theta()[1],
            'eta1': self.config.eta1,
            'eta2': self.config.eta2,
            'eta3': self.config.eta3
        }

        # Get baseline rankings
        self.baseline_rankings = self.patch_prioritizer.rank_patches(
            test_data,
            analysis_level=getattr(AnalysisLevel, analysis_level.upper())
        )

        logger.info(f"Set baseline with {len(self.baseline_rankings)} vulnerabilities")
        logger.info(f"Baseline parameters: {self.baseline_parameters}")

    # ============ Correlation Metrics ============

    def calculate_kendalls_tau(self, rankings1: List[Dict], rankings2: List[Dict]) -> Tuple[float, float]:
        """
        Calculate Kendall's Tau correlation with p-value

        Returns:
            Tuple of (tau, p_value)
        """
        if not rankings1 or not rankings2:
            return 0.0, 1.0

        # Extract CVE IDs and create ranking maps
        cve_rank1 = {rank['cve_id']: idx for idx, rank in enumerate(rankings1)}
        cve_rank2 = {rank['cve_id']: idx for idx, rank in enumerate(rankings2)}

        # Find common CVEs
        common_cves = set(cve_rank1.keys()) & set(cve_rank2.keys())
        if len(common_cves) < 2:
            return 0.0, 1.0

        # Create ranking arrays for common CVEs
        ranks1 = [cve_rank1[cve] for cve in sorted(common_cves)]
        ranks2 = [cve_rank2[cve] for cve in sorted(common_cves)]

        # Calculate Kendall's Tau
        try:
            tau, p_value = kendalltau(ranks1, ranks2)
            return tau, p_value
        except Exception as e:
            logger.warning(f"Error calculating Kendall's Tau: {e}")
            return 0.0, 1.0

    def calculate_spearman_correlation(self, rankings1: List[Dict], rankings2: List[Dict]) -> Tuple[float, float]:
        """
        Calculate Spearman's rank correlation with p-value

        Returns:
            Tuple of (rho, p_value)
        """
        if not rankings1 or not rankings2:
            return 0.0, 1.0

        # Extract common CVEs and their ranks
        cve_rank1 = {rank['cve_id']: idx for idx, rank in enumerate(rankings1)}
        cve_rank2 = {rank['cve_id']: idx for idx, rank in enumerate(rankings2)}
        common_cves = set(cve_rank1.keys()) & set(cve_rank2.keys())

        if len(common_cves) < 2:
            return 0.0, 1.0

        ranks1 = [cve_rank1[cve] for cve in sorted(common_cves)]
        ranks2 = [cve_rank2[cve] for cve in sorted(common_cves)]

        try:
            rho, p_value = spearmanr(ranks1, ranks2)
            return rho, p_value
        except Exception as e:
            logger.warning(f"Error calculating Spearman correlation: {e}")
            return 0.0, 1.0

    def calculate_weighted_kendalls_tau(self, rankings1: List[Dict], rankings2: List[Dict],
                                        weight_scheme: str = 'hyperbolic') -> float:
        """
        Calculate weighted Kendall's Tau giving more importance to top ranks

        Args:
            weight_scheme: 'hyperbolic', 'top_k', or 'exponential'
        """
        if not rankings1 or not rankings2:
            return 0.0

        # Get common CVEs
        cve_rank1 = {rank['cve_id']: idx for idx, rank in enumerate(rankings1)}
        cve_rank2 = {rank['cve_id']: idx for idx, rank in enumerate(rankings2)}
        common_cves = sorted(set(cve_rank1.keys()) & set(cve_rank2.keys()))

        if len(common_cves) < 2:
            return 0.0

        n = len(common_cves)

        # Define weights based on scheme
        if weight_scheme == 'hyperbolic':
            weights = {cve: 1.0 / (min(cve_rank1[cve], cve_rank2[cve]) + 1) for cve in common_cves}
        elif weight_scheme == 'exponential':
            weights = {cve: np.exp(-min(cve_rank1[cve], cve_rank2[cve]) / 10) for cve in common_cves}
        elif weight_scheme == 'top_k':
            k = min(20, n // 5)
            weights = {cve: 1.0 if min(cve_rank1[cve], cve_rank2[cve]) < k else 0.1 for cve in common_cves}
        else:
            weights = {cve: 1.0 for cve in common_cves}

        # Calculate weighted concordant and discordant pairs
        weighted_concordant = 0
        weighted_discordant = 0
        total_weight = 0

        for i, cve_i in enumerate(common_cves):
            for j, cve_j in enumerate(common_cves[i + 1:], i + 1):
                weight = weights[cve_i] * weights[cve_j]
                total_weight += weight

                # Check if pair is concordant or discordant
                rank_diff_1 = cve_rank1[cve_i] - cve_rank1[cve_j]
                rank_diff_2 = cve_rank2[cve_i] - cve_rank2[cve_j]

                if rank_diff_1 * rank_diff_2 > 0:
                    weighted_concordant += weight
                elif rank_diff_1 * rank_diff_2 < 0:
                    weighted_discordant += weight

        if total_weight == 0:
            return 0.0

        return (weighted_concordant - weighted_discordant) / total_weight

    def calculate_top_k_overlap(self, rankings1: List[Dict], rankings2: List[Dict],
                                k_values: List[int] = [5, 10, 20]) -> Dict[int, float]:
        """
        Calculate Jaccard similarity for top-K vulnerabilities
        """
        overlaps = {}

        for k in k_values:
            if k > len(rankings1) or k > len(rankings2):
                continue

            top_k_1 = set(r['cve_id'] for r in rankings1[:k])
            top_k_2 = set(r['cve_id'] for r in rankings2[:k])

            if not top_k_1 or not top_k_2:
                overlaps[k] = 0.0
            else:
                intersection = len(top_k_1 & top_k_2)
                union = len(top_k_1 | top_k_2)
                overlaps[k] = intersection / union if union > 0 else 0.0

        return overlaps

    def calculate_rank_biased_overlap(self, rankings1: List[Dict], rankings2: List[Dict],
                                      p: float = 0.9) -> float:
        """
        Calculate Rank-Biased Overlap (RBO)

        Args:
            p: persistence parameter (0.9 = top 10 ranks get 86% of weight)
        """
        if not rankings1 or not rankings2:
            return 0.0

        # Extract CVE lists
        list1 = [r['cve_id'] for r in rankings1]
        list2 = [r['cve_id'] for r in rankings2]

        # Calculate RBO
        rbo_sum = 0.0
        agreement = 0.0

        for depth in range(1, min(len(list1), len(list2)) + 1):
            set1 = set(list1[:depth])
            set2 = set(list2[:depth])

            agreement = len(set1 & set2) / depth
            weight = (1 - p) * (p ** (depth - 1))
            rbo_sum += weight * agreement

        # Add residual weight for the tail
        if p < 1:
            residual = p ** min(len(list1), len(list2))
            rbo_sum += residual * agreement

        return rbo_sum

    # ============ Variance-Based Sensitivity Analysis ============

    def calculate_sobol_indices(self, test_data: Union[Asset, System],
                                n_samples: int = 1000) -> Dict[str, Dict[str, float]]:
        """
        Calculate first-order and total Sobol sensitivity indices
        """
        if not SALIB_AVAILABLE:
            logger.warning("SALib not available. Skipping Sobol analysis.")
            return {}

        logger.info(f"Calculating Sobol indices with {n_samples} samples...")

        # Define problem
        problem = {
            'num_vars': 5,
            'names': ['delta', 'theta', 'eta1', 'eta2', 'eta3'],
            'bounds': [[0.3, 0.7], [0.3, 0.7], [0.1, 0.5], [0.1, 0.5], [0.1, 0.5]]
        }

        # Generate samples using Saltelli's scheme
        param_values = saltelli.sample(problem, n_samples)

        # Evaluate model for each sample
        Y = np.zeros(param_values.shape[0])

        logger.info(f"Evaluating {param_values.shape[0]} parameter combinations...")

        for i, params in enumerate(param_values):
            if i % 100 == 0:
                logger.debug(f"Processing sample {i}/{param_values.shape[0]}")

            # Ensure constraints are met
            delta, theta = params[0], params[1]
            if abs(delta + theta - 1.0) > 0.001:
                theta = 1.0 - delta

            eta1, eta2, eta3 = params[2], params[3], params[4]
            eta_sum = eta1 + eta2 + eta3
            if abs(eta_sum - 1.0) > 0.001:
                # Normalize
                eta1, eta2, eta3 = eta1 / eta_sum, eta2 / eta_sum, eta3 / eta_sum

            # Update parameters and get metric
            update_parameters(delta=delta, theta=theta, eta1=eta1, eta2=eta2, eta3=eta3)

            try:
                rankings = self.patch_prioritizer.rank_patches(
                    test_data,
                    analysis_level=getattr(AnalysisLevel, self.analysis_level.upper())
                )

                # Use mean priority score as output metric
                Y[i] = np.mean([r.get('priority_score', 0) for r in rankings])
            except Exception as e:
                logger.warning(f"Error in sample {i}: {e}")
                Y[i] = 0.0

        # Restore baseline parameters
        if self.baseline_parameters:
            update_parameters(**self.baseline_parameters)

        # Calculate Sobol indices
        Si = sobol.analyze(problem, Y)

        return {
            'first_order': dict(zip(problem['names'], Si['S1'])),
            'total_order': dict(zip(problem['names'], Si['ST'])),
            'second_order': Si.get('S2', {}),
            'confidence_intervals': {
                'S1_conf': dict(zip(problem['names'], Si.get('S1_conf', [[0, 0]] * 5))),
                'ST_conf': dict(zip(problem['names'], Si.get('ST_conf', [[0, 0]] * 5)))
            }
        }

    # ============ Parameter Interaction Analysis ============

    def analyze_parameter_interactions(self, results_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Analyze interactions between parameters using ANOVA and regression
        """
        # Extract mean priorities for analysis
        mean_priorities = []
        for metrics in results_df['ranking_metrics']:
            if isinstance(metrics, dict):
                mean_priorities.append(metrics.get('mean_priority', 0))
            else:
                mean_priorities.append(0)

        results_df = results_df.copy()
        results_df['mean_priority'] = mean_priorities

        interactions = {}

        # 1. Two-way ANOVA for applicable parameter combinations
        if 'delta' in results_df.columns and 'theta' in results_df.columns:
            try:
                # Convert to categorical for ANOVA
                results_df['delta_cat'] = pd.Categorical(results_df['delta'].round(1))
                results_df['theta_cat'] = pd.Categorical(results_df['theta'].round(1))

                formula = 'mean_priority ~ C(delta_cat) + C(theta_cat) + C(delta_cat):C(theta_cat)'
                model = ols(formula, data=results_df).fit()
                anova_table = sm.stats.anova_lm(model, typ=2)

                interactions['anova_delta_theta'] = {
                    'table': anova_table.to_dict(),
                    'r_squared': model.rsquared,
                    'f_statistic': model.fvalue,
                    'p_value': model.f_pvalue
                }
            except Exception as e:
                logger.warning(f"ANOVA failed: {e}")

        # 2. Polynomial regression for non-linear effects
        param_cols = [col for col in ['delta', 'theta', 'eta1', 'eta2', 'eta3'] if col in results_df.columns]

        if len(param_cols) >= 2:
            X = results_df[param_cols].values
            y = results_df['mean_priority'].values

            # Include interaction terms
            poly = PolynomialFeatures(degree=2, include_bias=False)
            X_poly = poly.fit_transform(X)

            model = LinearRegression()
            model.fit(X_poly, y)
            y_pred = model.predict(X_poly)

            # Get feature names
            feature_names = poly.get_feature_names_out(param_cols)

            interactions['polynomial_regression'] = {
                'r2_score': r2_score(y, y_pred),
                'coefficients': dict(zip(feature_names, model.coef_)),
                'intercept': model.intercept_,
                'feature_importance': {
                    name: abs(coef) for name, coef in zip(feature_names, model.coef_)
                }
            }

        # 3. Correlation matrix
        if len(param_cols) >= 2:
            corr_data = results_df[param_cols + ['mean_priority']].corr()
            interactions['correlation_matrix'] = corr_data.to_dict()

        return interactions

    # ============ Bootstrap Analysis ============

    def calculate_bootstrap_confidence_intervals(self, test_data: Union[Asset, System],
                                                 n_bootstrap: int = None,
                                                 confidence_level: float = None) -> Dict[str, Any]:
        """
        Calculate bootstrap confidence intervals for ranking stability
        """
        if n_bootstrap is None:
            n_bootstrap = self.n_bootstrap
        if confidence_level is None:
            confidence_level = self.confidence_level

        logger.info(f"Calculating bootstrap confidence intervals with {n_bootstrap} iterations...")

        bootstrap_results = []

        # Get baseline scores for resampling
        baseline_scores = [r.get('priority_score', 0) for r in self.baseline_rankings]
        baseline_cves = [r['cve_id'] for r in self.baseline_rankings]
        n_vulns = len(baseline_scores)

        for i in range(n_bootstrap):
            if i % 100 == 0:
                logger.debug(f"Bootstrap iteration {i}/{n_bootstrap}")

            # Resample indices with replacement
            indices = np.random.choice(n_vulns, n_vulns, replace=True)

            # Create resampled rankings
            resampled_rankings = [self.baseline_rankings[idx] for idx in indices]

            # Calculate metrics for bootstrap sample
            scores = [r.get('priority_score', 0) for r in resampled_rankings]

            bootstrap_results.append({
                'mean_priority': np.mean(scores),
                'std_priority': np.std(scores),
                'median_priority': np.median(scores),
                'n_high_priority': len([s for s in scores if s > 7.0]),
                'n_medium_priority': len([s for s in scores if 4.0 <= s <= 7.0]),
                'n_low_priority': len([s for s in scores if s < 4.0])
            })

        # Calculate confidence intervals
        alpha = 1 - confidence_level
        lower_percentile = (alpha / 2) * 100
        upper_percentile = (1 - alpha / 2) * 100

        confidence_intervals = {}
        for metric in bootstrap_results[0].keys():
            values = [r[metric] for r in bootstrap_results]
            confidence_intervals[metric] = {
                'mean': np.mean(values),
                'std': np.std(values),
                'ci_lower': np.percentile(values, lower_percentile),
                'ci_upper': np.percentile(values, upper_percentile),
                'median': np.median(values)
            }

        return confidence_intervals

    # ============ Score Distribution Analysis ============

    def analyze_score_distributions(self, results: Dict[str, pd.DataFrame]) -> Dict[str, Any]:
        """
        Analyze how score distributions change with parameters
        """
        logger.info("Analyzing score distributions across parameter combinations...")

        distribution_analysis = {}

        for param_group, results_df in results.items():
            if results_df.empty:
                continue

            distributions = []

            for idx, row in results_df.iterrows():
                # Get full rankings for this parameter combination
                if param_group == 'delta_theta':
                    update_parameters(delta=row['delta'], theta=row['theta'])
                elif param_group == 'exploit_score':
                    update_parameters(eta1=row['eta1'], eta2=row['eta2'], eta3=row['eta3'])

                try:
                    rankings = self.patch_prioritizer.rank_patches(
                        self.test_data,
                        analysis_level=getattr(AnalysisLevel, self.analysis_level.upper())
                    )
                    scores = [r.get('priority_score', 0) for r in rankings]

                    if len(scores) < 4:  # Need at least 4 values for these tests
                        continue

                    # Analyze distribution
                    shapiro_stat, shapiro_p = shapiro(scores) if len(scores) >= 3 else (np.nan, np.nan)

                    dist_stats = {
                        'params': row.to_dict(),
                        'mean': np.mean(scores),
                        'median': np.median(scores),
                        'std': np.std(scores),
                        'skewness': skew(scores),
                        'kurtosis': kurtosis(scores),
                        'shapiro_test': {
                            'statistic': shapiro_stat,
                            'p_value': shapiro_p,
                            'is_normal': shapiro_p > 0.05 if not np.isnan(shapiro_p) else None
                        },
                        'percentiles': {
                            '10': np.percentile(scores, 10),
                            '25': np.percentile(scores, 25),
                            '50': np.percentile(scores, 50),
                            '75': np.percentile(scores, 75),
                            '90': np.percentile(scores, 90),
                            '95': np.percentile(scores, 95)
                        },
                        'iqr': np.percentile(scores, 75) - np.percentile(scores, 25)
                    }

                    distributions.append(dist_stats)

                except Exception as e:
                    logger.warning(f"Error analyzing distribution for {row.to_dict()}: {e}")
                    continue

            distribution_analysis[param_group] = distributions

        # Restore baseline parameters
        if self.baseline_parameters:
            update_parameters(**self.baseline_parameters)

        return distribution_analysis

    # ============ Parameter Sweep Methods ============

    def sweep_delta_theta(self, test_data: Union[Asset, System],
                          analysis_level: str = "asset") -> pd.DataFrame:
        """
        Sweep δ and θ parameters and analyze impact on risk rankings
        """
        logger.info("Starting δ and θ parameter sweep...")

        results = []

        # Get baseline parameters
        baseline_delta, baseline_theta = get_delta_theta()

        # Sweep through δ and θ combinations
        for delta in self.parameter_ranges['delta']:
            for theta in self.parameter_ranges['theta']:
                # Skip combinations where δ + θ ≠ 1.0
                if abs(delta + theta - 1.0) > 0.001:
                    continue

                logger.debug(f"Testing δ={delta:.1f}, θ={theta:.1f}")

                # Update global parameters
                update_parameters(delta=delta, theta=theta)

                try:
                    # Calculate risk rankings with current parameters
                    rankings = self.patch_prioritizer.rank_patches(
                        test_data,
                        analysis_level=getattr(AnalysisLevel, analysis_level.upper())
                    )

                    # Calculate correlation metrics with baseline
                    tau, tau_p = self.calculate_kendalls_tau(self.baseline_rankings, rankings)
                    rho, rho_p = self.calculate_spearman_correlation(self.baseline_rankings, rankings)
                    weighted_tau = self.calculate_weighted_kendalls_tau(self.baseline_rankings, rankings)
                    rbo = self.calculate_rank_biased_overlap(self.baseline_rankings, rankings)
                    top_k_overlap = self.calculate_top_k_overlap(self.baseline_rankings, rankings)

                    # Extract ranking information
                    ranking_data = self._extract_ranking_data(rankings)

                    # Calculate ranking metrics
                    metrics = self._calculate_ranking_metrics(rankings)

                    # Store results
                    result = {
                        'delta': delta,
                        'theta': theta,
                        'ranking_metrics': metrics,
                        'correlation_metrics': {
                            'kendalls_tau': tau,
                            'kendalls_tau_p': tau_p,
                            'spearman_rho': rho,
                            'spearman_p': rho_p,
                            'weighted_kendalls_tau': weighted_tau,
                            'rank_biased_overlap': rbo,
                            'top_k_overlap': top_k_overlap
                        },
                        'top_vulnerabilities': ranking_data['top_5'],
                        'ranking_changes': ranking_data['changes']
                    }

                    results.append(result)

                except Exception as e:
                    logger.error(f"Error with δ={delta}, θ={theta}: {e}")
                    continue

        # Restore baseline parameters
        update_parameters(delta=baseline_delta, theta=baseline_theta)

        # Convert to DataFrame
        results_df = pd.DataFrame(results)

        # Save results
        self._save_delta_theta_results(results_df)

        logger.info(f"Completed δ and θ sweep: {len(results_df)} valid combinations")
        return results_df

    def sweep_exploit_score_params(self, test_data: Union[Asset, System],
                                   analysis_level: str = "asset") -> pd.DataFrame:
        """
        Sweep η1, η2, η3 parameters for ExploitScore calculation
        """
        logger.info("Starting η1, η2, η3 parameter sweep...")

        results = []

        # Store baseline eta values
        baseline_eta1 = self.config.eta1
        baseline_eta2 = self.config.eta2
        baseline_eta3 = self.config.eta3

        # Sweep through η1, η2, η3 combinations
        for eta1 in self.parameter_ranges['eta1']:
            for eta2 in self.parameter_ranges['eta2']:
                for eta3 in self.parameter_ranges['eta3']:
                    # Skip combinations where η1 + η2 + η3 ≠ 1.0
                    if abs(eta1 + eta2 + eta3 - 1.0) > 0.001:
                        continue

                    logger.debug(f"Testing η1={eta1:.1f}, η2={eta2:.1f}, η3={eta3:.1f}")

                    # Update global parameters
                    update_parameters(eta1=eta1, eta2=eta2, eta3=eta3)

                    try:
                        # Calculate risk rankings with current parameters
                        rankings = self.patch_prioritizer.rank_patches(
                            test_data,
                            analysis_level=getattr(AnalysisLevel, analysis_level.upper())
                        )

                        # Calculate correlation metrics
                        tau, tau_p = self.calculate_kendalls_tau(self.baseline_rankings, rankings)
                        rho, rho_p = self.calculate_spearman_correlation(self.baseline_rankings, rankings)
                        weighted_tau = self.calculate_weighted_kendalls_tau(self.baseline_rankings, rankings)
                        rbo = self.calculate_rank_biased_overlap(self.baseline_rankings, rankings)
                        top_k_overlap = self.calculate_top_k_overlap(self.baseline_rankings, rankings)

                        # Extract ranking information
                        ranking_data = self._extract_ranking_data(rankings)

                        # Calculate ranking metrics
                        metrics = self._calculate_ranking_metrics(rankings)

                        # Store results
                        result = {
                            'eta1': eta1,
                            'eta2': eta2,
                            'eta3': eta3,
                            'ranking_metrics': metrics,
                            'correlation_metrics': {
                                'kendalls_tau': tau,
                                'kendalls_tau_p': tau_p,
                                'spearman_rho': rho,
                                'spearman_p': rho_p,
                                'weighted_kendalls_tau': weighted_tau,
                                'rank_biased_overlap': rbo,
                                'top_k_overlap': top_k_overlap
                            },
                            'top_vulnerabilities': ranking_data['top_5'],
                            'ranking_changes': ranking_data['changes']
                        }

                        results.append(result)

                    except Exception as e:
                        logger.error(f"Error with η1={eta1}, η2={eta2}, η3={eta3}: {e}")
                        continue

        # Restore baseline parameters
        update_parameters(eta1=baseline_eta1, eta2=baseline_eta2, eta3=baseline_eta3)

        # Convert to DataFrame
        results_df = pd.DataFrame(results)

        # Save results
        self._save_exploit_score_results(results_df)

        logger.info(f"Completed η1, η2, η3 sweep: {len(results_df)} valid combinations")
        return results_df

    # ============ Visualization Methods ============

    def create_advanced_visualizations(self, comprehensive_results: Dict[str, Any]) -> None:
        """
        Create publication-quality visualizations
        """
        logger.info("Creating advanced visualizations...")

        # Set publication style
        plt.style.use('seaborn-v0_8-paper')
        plt.rcParams['font.size'] = 12
        plt.rcParams['axes.labelsize'] = 14
        plt.rcParams['axes.titlesize'] = 16
        plt.rcParams['xtick.labelsize'] = 12
        plt.rcParams['ytick.labelsize'] = 12
        plt.rcParams['legend.fontsize'] = 12

        # 1. Generate basic heatmaps
        if 'sweep_results' in comprehensive_results:
            self.generate_sensitivity_heatmaps(comprehensive_results['sweep_results'])

        # 2. Sobol indices visualization
        if 'sobol_indices' in comprehensive_results and comprehensive_results['sobol_indices']:
            self._plot_sobol_indices(comprehensive_results['sobol_indices'])

        # 3. Correlation analysis plots
        if 'sweep_results' in comprehensive_results:
            for param_group, df in comprehensive_results['sweep_results'].items():
                if not df.empty:
                    self._create_correlation_plots(df, param_group)

        # 4. Stability analysis charts
        if 'stability_analysis' in comprehensive_results:
            self._create_stability_charts(comprehensive_results['stability_analysis'])

        # 5. Bootstrap confidence intervals
        if 'bootstrap_ci' in comprehensive_results:
            self._plot_bootstrap_intervals(comprehensive_results['bootstrap_ci'])

        # 6. Score distribution plots
        if 'distribution_analysis' in comprehensive_results:
            self._plot_score_distributions(comprehensive_results['distribution_analysis'])

        # 7. Parameter interaction surfaces
        if 'interaction_analysis' in comprehensive_results:
            self._plot_interaction_surfaces(comprehensive_results['interaction_analysis'])

    def _plot_sobol_indices(self, sobol_data: Dict[str, Dict[str, float]]) -> None:
        """Create bar plot of Sobol sensitivity indices"""
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

        # First-order indices
        params = list(sobol_data['first_order'].keys())
        s1_values = list(sobol_data['first_order'].values())

        bars1 = ax1.bar(params, s1_values, alpha=0.7, color='steelblue', edgecolor='black')
        ax1.set_xlabel('Parameters')
        ax1.set_ylabel('First-Order Sobol Index')
        ax1.set_title('First-Order Sensitivity Indices')
        ax1.set_ylim(0, 1)
        ax1.grid(True, alpha=0.3, axis='y')

        # Add value labels on bars
        for bar, value in zip(bars1, s1_values):
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width() / 2., height + 0.02,
                     f'{value:.3f}', ha='center', va='bottom')

        # Total-order indices
        st_values = list(sobol_data['total_order'].values())

        bars2 = ax2.bar(params, st_values, alpha=0.7, color='darkred', edgecolor='black')
        ax2.set_xlabel('Parameters')
        ax2.set_ylabel('Total-Order Sobol Index')
        ax2.set_title('Total-Order Sensitivity Indices (Including Interactions)')
        ax2.set_ylim(0, 1)
        ax2.grid(True, alpha=0.3, axis='y')

        # Add value labels
        for bar, value in zip(bars2, st_values):
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width() / 2., height + 0.02,
                     f'{value:.3f}', ha='center', va='bottom')

        plt.tight_layout()
        plt.savefig(self.results_dir / "sobol_indices.png", dpi=300, bbox_inches='tight')
        plt.close()

        # Create interaction heatmap if second-order indices are available
        if 'second_order' in sobol_data and sobol_data['second_order']:
            self._plot_second_order_sobol(sobol_data['second_order'], params)

    def _plot_second_order_sobol(self, second_order: Dict, params: List[str]) -> None:
        """Plot second-order Sobol indices as heatmap"""
        n_params = len(params)
        interaction_matrix = np.zeros((n_params, n_params))

        # Fill interaction matrix
        for i, param1 in enumerate(params):
            for j, param2 in enumerate(params):
                if i < j:
                    key = (i, j)
                    if key in second_order:
                        interaction_matrix[i, j] = second_order[key]
                        interaction_matrix[j, i] = second_order[key]

        plt.figure(figsize=(10, 8))
        sns.heatmap(interaction_matrix, annot=True, fmt='.3f', cmap='YlOrRd',
                    xticklabels=params, yticklabels=params,
                    cbar_kws={'label': 'Second-Order Sobol Index'})
        plt.title('Parameter Interaction Effects (Second-Order Sobol Indices)')
        plt.tight_layout()
        plt.savefig(self.results_dir / "sobol_interactions.png", dpi=300, bbox_inches='tight')
        plt.close()

    def _create_correlation_plots(self, results_df: pd.DataFrame, param_group: str) -> None:
        """Create correlation plots for parameter relationships"""
        if results_df.empty:
            return

        # Extract metrics
        mean_priorities = []
        kendalls_taus = []
        spearman_rhos = []
        rbos = []

        for _, row in results_df.iterrows():
            if isinstance(row['ranking_metrics'], dict):
                mean_priorities.append(row['ranking_metrics'].get('mean_priority', 0))
            else:
                mean_priorities.append(0)

            if isinstance(row.get('correlation_metrics'), dict):
                kendalls_taus.append(row['correlation_metrics'].get('kendalls_tau', 0))
                spearman_rhos.append(row['correlation_metrics'].get('spearman_rho', 0))
                rbos.append(row['correlation_metrics'].get('rank_biased_overlap', 0))
            else:
                kendalls_taus.append(0)
                spearman_rhos.append(0)
                rbos.append(0)

        # Create comprehensive correlation plot
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))

        if param_group == 'delta_theta':
            # δ vs Mean Priority
            sc1 = axes[0, 0].scatter(results_df['delta'], mean_priorities,
                                     c=results_df['theta'], cmap='viridis', alpha=0.7, s=100)
            axes[0, 0].set_xlabel('δ (Network Posture Weight)')
            axes[0, 0].set_ylabel('Mean Priority Score')
            axes[0, 0].set_title('δ vs Mean Priority (colored by θ)')
            axes[0, 0].grid(True, alpha=0.3)
            plt.colorbar(sc1, ax=axes[0, 0], label='θ')

            # θ vs Mean Priority
            sc2 = axes[0, 1].scatter(results_df['theta'], mean_priorities,
                                     c=results_df['delta'], cmap='plasma', alpha=0.7, s=100)
            axes[0, 1].set_xlabel('θ (Attack Pattern History Weight)')
            axes[0, 1].set_ylabel('Mean Priority Score')
            axes[0, 1].set_title('θ vs Mean Priority (colored by δ)')
            axes[0, 1].grid(True, alpha=0.3)
            plt.colorbar(sc2, ax=axes[0, 1], label='δ')

            # Parameter space with Kendall's Tau
            sc3 = axes[0, 2].scatter(results_df['delta'], results_df['theta'],
                                     c=kendalls_taus, cmap='RdYlBu', alpha=0.7, s=100,
                                     vmin=0, vmax=1)
            axes[0, 2].set_xlabel('δ (Network Posture Weight)')
            axes[0, 2].set_ylabel('θ (Attack Pattern History Weight)')
            axes[0, 2].set_title("Parameter Space colored by Kendall's Tau")
            axes[0, 2].grid(True, alpha=0.3)
            plt.colorbar(sc3, ax=axes[0, 2], label="Kendall's Tau")

        elif param_group == 'exploit_score':
            # 3D parameter space projections
            # η1 vs η2
            sc1 = axes[0, 0].scatter(results_df['eta1'], results_df['eta2'],
                                     c=mean_priorities, cmap='viridis', alpha=0.7, s=100)
            axes[0, 0].set_xlabel('η1 (Known Exploit Weight)')
            axes[0, 0].set_ylabel('η2 (Predicted Exploit Weight)')
            axes[0, 0].set_title('η1 vs η2 (colored by Mean Priority)')
            axes[0, 0].grid(True, alpha=0.3)
            plt.colorbar(sc1, ax=axes[0, 0], label='Mean Priority')

            # η1 vs η3
            sc2 = axes[0, 1].scatter(results_df['eta1'], results_df['eta3'],
                                     c=kendalls_taus, cmap='RdYlBu', alpha=0.7, s=100,
                                     vmin=0, vmax=1)
            axes[0, 1].set_xlabel('η1 (Known Exploit Weight)')
            axes[0, 1].set_ylabel('η3 (Zero-day Likelihood Weight)')
            axes[0, 1].set_title("η1 vs η3 (colored by Kendall's Tau)")
            axes[0, 1].grid(True, alpha=0.3)
            plt.colorbar(sc2, ax=axes[0, 1], label="Kendall's Tau")

            # η2 vs η3
            sc3 = axes[0, 2].scatter(results_df['eta2'], results_df['eta3'],
                                     c=rbos, cmap='plasma', alpha=0.7, s=100)
            axes[0, 2].set_xlabel('η2 (Predicted Exploit Weight)')
            axes[0, 2].set_ylabel('η3 (Zero-day Likelihood Weight)')
            axes[0, 2].set_title('η2 vs η3 (colored by RBO)')
            axes[0, 2].grid(True, alpha=0.3)
            plt.colorbar(sc3, ax=axes[0, 2], label='Rank-Biased Overlap')

        # Correlation metrics distributions
        axes[1, 0].hist(kendalls_taus, bins=20, alpha=0.7, edgecolor='black')
        axes[1, 0].set_xlabel("Kendall's Tau")
        axes[1, 0].set_ylabel('Frequency')
        axes[1, 0].set_title("Distribution of Kendall's Tau Values")
        axes[1, 0].axvline(np.mean(kendalls_taus), color='red', linestyle='--',
                           label=f'Mean: {np.mean(kendalls_taus):.3f}')
        axes[1, 0].legend()
        axes[1, 0].grid(True, alpha=0.3)

        axes[1, 1].hist(spearman_rhos, bins=20, alpha=0.7, edgecolor='black', color='green')
        axes[1, 1].set_xlabel("Spearman's Rho")
        axes[1, 1].set_ylabel('Frequency')
        axes[1, 1].set_title("Distribution of Spearman's Rho Values")
        axes[1, 1].axvline(np.mean(spearman_rhos), color='red', linestyle='--',
                           label=f'Mean: {np.mean(spearman_rhos):.3f}')
        axes[1, 1].legend()
        axes[1, 1].grid(True, alpha=0.3)

        axes[1, 2].hist(rbos, bins=20, alpha=0.7, edgecolor='black', color='orange')
        axes[1, 2].set_xlabel('Rank-Biased Overlap')
        axes[1, 2].set_ylabel('Frequency')
        axes[1, 2].set_title('Distribution of RBO Values')
        axes[1, 2].axvline(np.mean(rbos), color='red', linestyle='--',
                           label=f'Mean: {np.mean(rbos):.3f}')
        axes[1, 2].legend()
        axes[1, 2].grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(self.results_dir / f"correlation_analysis_{param_group}.png",
                    dpi=300, bbox_inches='tight')
        plt.close()

    def _plot_bootstrap_intervals(self, bootstrap_ci: Dict[str, Dict[str, float]]) -> None:
        """Plot bootstrap confidence intervals"""
        metrics = list(bootstrap_ci.keys())

        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        axes = axes.flatten()

        for idx, (metric, ci_data) in enumerate(bootstrap_ci.items()):
            if idx >= 4:
                break

            ax = axes[idx]

            # Create error bar plot
            mean_val = ci_data['mean']
            ci_lower = ci_data['ci_lower']
            ci_upper = ci_data['ci_upper']

            # Plot confidence interval
            ax.errorbar([0], [mean_val],
                        yerr=[[mean_val - ci_lower], [ci_upper - mean_val]],
                        fmt='o', markersize=10, capsize=10, capthick=2,
                        label=f'95% CI: [{ci_lower:.3f}, {ci_upper:.3f}]')

            # Add median line
            ax.axhline(ci_data['median'], color='red', linestyle='--',
                       alpha=0.7, label=f'Median: {ci_data["median"]:.3f}')

            ax.set_xlim(-0.5, 0.5)
            ax.set_ylabel(metric.replace('_', ' ').title())
            ax.set_title(f'Bootstrap CI for {metric.replace("_", " ").title()}')
            ax.legend()
            ax.grid(True, alpha=0.3)
            ax.set_xticks([])

        plt.tight_layout()
        plt.savefig(self.results_dir / "bootstrap_confidence_intervals.png",
                    dpi=300, bbox_inches='tight')
        plt.close()

    def _plot_score_distributions(self, distribution_analysis: Dict[str, List[Dict]]) -> None:
        """Create violin plots of score distributions"""
        for param_group, distributions in distribution_analysis.items():
            if not distributions:
                continue

            fig, axes = plt.subplots(2, 2, figsize=(15, 12))

            # Extract data for plotting
            all_params = []
            all_means = []
            all_stds = []
            all_skewness = []
            all_kurtosis = []

            for dist in distributions:
                params = dist['params']
                param_str = ', '.join([f'{k}={v:.1f}' for k, v in params.items()])
                all_params.append(param_str)
                all_means.append(dist['mean'])
                all_stds.append(dist['std'])
                all_skewness.append(dist['skewness'])
                all_kurtosis.append(dist['kurtosis'])

            # Plot distributions of distribution statistics
            axes[0, 0].scatter(range(len(all_means)), all_means, alpha=0.6)
            axes[0, 0].set_ylabel('Mean Score')
            axes[0, 0].set_title('Mean Scores Across Parameter Combinations')
            axes[0, 0].grid(True, alpha=0.3)

            axes[0, 1].scatter(range(len(all_stds)), all_stds, alpha=0.6, color='orange')
            axes[0, 1].set_ylabel('Standard Deviation')
            axes[0, 1].set_title('Score Variability Across Parameter Combinations')
            axes[0, 1].grid(True, alpha=0.3)

            axes[1, 0].scatter(range(len(all_skewness)), all_skewness, alpha=0.6, color='green')
            axes[1, 0].set_ylabel('Skewness')
            axes[1, 0].set_title('Distribution Skewness Across Parameter Combinations')
            axes[1, 0].axhline(0, color='red', linestyle='--', alpha=0.5)
            axes[1, 0].grid(True, alpha=0.3)

            axes[1, 1].scatter(range(len(all_kurtosis)), all_kurtosis, alpha=0.6, color='red')
            axes[1, 1].set_ylabel('Kurtosis')
            axes[1, 1].set_title('Distribution Kurtosis Across Parameter Combinations')
            axes[1, 1].axhline(0, color='black', linestyle='--', alpha=0.5)
            axes[1, 1].grid(True, alpha=0.3)

            for ax in axes.flatten():
                ax.set_xlabel('Parameter Combination Index')

            plt.tight_layout()
            plt.savefig(self.results_dir / f"score_distributions_{param_group}.png",
                        dpi=300, bbox_inches='tight')
            plt.close()

    def _plot_interaction_surfaces(self, interaction_analysis: Dict[str, Dict]) -> None:
        """Plot parameter interaction surfaces"""
        for param_group, interactions in interaction_analysis.items():
            if 'polynomial_regression' not in interactions:
                continue

            # Create feature importance plot
            poly_data = interactions['polynomial_regression']
            if 'feature_importance' not in poly_data:
                continue

            # Sort features by importance
            features = list(poly_data['feature_importance'].keys())
            importances = list(poly_data['feature_importance'].values())

            # Sort by importance
            sorted_idx = np.argsort(importances)[::-1][:15]  # Top 15 features
            top_features = [features[i] for i in sorted_idx]
            top_importances = [importances[i] for i in sorted_idx]

            plt.figure(figsize=(12, 8))
            bars = plt.bar(range(len(top_features)), top_importances, alpha=0.7)
            plt.xlabel('Feature')
            plt.ylabel('Absolute Coefficient Value')
            plt.title(f'Top Feature Importance in {param_group} Polynomial Model\n(R² = {poly_data["r2_score"]:.3f})')
            plt.xticks(range(len(top_features)), top_features, rotation=45, ha='right')

            # Color bars by type
            for i, (bar, feature) in enumerate(zip(bars, top_features)):
                if '^2' in feature:
                    bar.set_color('darkred')
                elif ' ' in feature:  # Interaction term
                    bar.set_color('darkblue')
                else:  # Linear term
                    bar.set_color('darkgreen')

            # Add legend
            from matplotlib.patches import Patch
            legend_elements = [
                Patch(facecolor='darkgreen', label='Linear Terms'),
                Patch(facecolor='darkred', label='Quadratic Terms'),
                Patch(facecolor='darkblue', label='Interaction Terms')
            ]
            plt.legend(handles=legend_elements, loc='upper right')

            plt.grid(True, alpha=0.3, axis='y')
            plt.tight_layout()
            plt.savefig(self.results_dir / f"feature_importance_{param_group}.png",
                        dpi=300, bbox_inches='tight')
            plt.close()

    def generate_sensitivity_heatmaps(self, results: Dict[str, pd.DataFrame]) -> None:
        """Generate sensitivity heatmaps for visualization"""
        # δ and θ heatmap
        if 'delta_theta' in results and not results['delta_theta'].empty:
            self._create_delta_theta_heatmap(results['delta_theta'])

        # η1, η2, η3 heatmap
        if 'exploit_score' in results and not results['exploit_score'].empty:
            self._create_exploit_score_heatmap(results['exploit_score'])

    def _create_delta_theta_heatmap(self, results_df: pd.DataFrame) -> None:
        """Create heatmap for δ and θ parameters"""
        if results_df.empty:
            return

        # Create multiple heatmaps for different metrics
        fig, axes = plt.subplots(2, 2, figsize=(16, 14))

        metrics_to_plot = [
            ('mean_priority', 'Mean Priority Score', 'viridis'),
            ('kendalls_tau', "Kendall's Tau with Baseline", 'RdYlBu'),
            ('rank_biased_overlap', 'Rank-Biased Overlap', 'plasma'),
            ('top_5_overlap', 'Top-5 Overlap', 'YlOrRd')
        ]

        for idx, (metric, title, cmap) in enumerate(metrics_to_plot):
            ax = axes[idx // 2, idx % 2]

            # Extract metric values
            if metric == 'mean_priority':
                values = [m.get('mean_priority', 0) if isinstance(m, dict) else 0
                          for m in results_df['ranking_metrics']]
            elif metric == 'kendalls_tau':
                values = [m.get('kendalls_tau', 0) if isinstance(m, dict) else 0
                          for m in results_df.get('correlation_metrics', [{}])]
            elif metric == 'rank_biased_overlap':
                values = [m.get('rank_biased_overlap', 0) if isinstance(m, dict) else 0
                          for m in results_df.get('correlation_metrics', [{}])]
            elif metric == 'top_5_overlap':
                values = [m.get(5, 0) if isinstance(m, dict) else 0
                          for m in [r.get('top_k_overlap', {}) if isinstance(r, dict) else {}
                                    for r in results_df.get('correlation_metrics', [{}])]]

            # Create pivot table
            results_df['metric_value'] = values
            pivot_data = results_df.pivot_table(
                values='metric_value',
                index='delta',
                columns='theta',
                aggfunc='mean'
            )

            # Create heatmap
            sns.heatmap(pivot_data, annot=True, fmt='.3f', cmap=cmap, ax=ax,
                        cbar_kws={'label': title})
            ax.set_title(f'{title} Heatmap')
            ax.set_xlabel('θ (Attack Pattern History Weight)')
            ax.set_ylabel('δ (Network Posture Weight)')

        plt.tight_layout()
        plt.savefig(self.results_dir / "delta_theta_heatmaps.png", dpi=300, bbox_inches='tight')
        plt.close()

    def _create_exploit_score_heatmap(self, results_df: pd.DataFrame) -> None:
        """Create heatmap for η1, η2, η3 parameters"""
        if results_df.empty:
            return

        # Create 2D projections for 3D parameter space
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))

        # Extract mean priorities
        mean_priorities = [m.get('mean_priority', 0) if isinstance(m, dict) else 0
                           for m in results_df['ranking_metrics']]
        results_df['mean_priority'] = mean_priorities

        # η1 vs η2 (averaging over η3)
        pivot_12 = results_df.pivot_table(
            values='mean_priority',
            index='eta1',
            columns='eta2',
            aggfunc='mean'
        )

        sns.heatmap(pivot_12, annot=True, fmt='.3f', cmap='viridis', ax=axes[0, 0],
                    cbar_kws={'label': 'Mean Priority'})
        axes[0, 0].set_title('η1 vs η2 (averaged over η3)')
        axes[0, 0].set_xlabel('η2 (Predicted Exploit Weight)')
        axes[0, 0].set_ylabel('η1 (Known Exploit Weight)')

        # η1 vs η3 (averaging over η2)
        pivot_13 = results_df.pivot_table(
            values='mean_priority',
            index='eta1',
            columns='eta3',
            aggfunc='mean'
        )

        sns.heatmap(pivot_13, annot=True, fmt='.3f', cmap='plasma', ax=axes[0, 1],
                    cbar_kws={'label': 'Mean Priority'})
        axes[0, 1].set_title('η1 vs η3 (averaged over η2)')
        axes[0, 1].set_xlabel('η3 (Zero-day Likelihood Weight)')
        axes[0, 1].set_ylabel('η1 (Known Exploit Weight)')

        # η2 vs η3 (averaging over η1)
        pivot_23 = results_df.pivot_table(
            values='mean_priority',
            index='eta2',
            columns='eta3',
            aggfunc='mean'
        )

        sns.heatmap(pivot_23, annot=True, fmt='.3f', cmap='YlOrRd', ax=axes[0, 2],
                    cbar_kws={'label': 'Mean Priority'})
        axes[0, 2].set_title('η2 vs η3 (averaged over η1)')
        axes[0, 2].set_xlabel('η3 (Zero-day Likelihood Weight)')
        axes[0, 2].set_ylabel('η2 (Predicted Exploit Weight)')

        # Similar plots for Kendall's Tau
        kendalls_taus = [m.get('kendalls_tau', 0) if isinstance(m, dict) else 0
                         for m in results_df.get('correlation_metrics', [{}])]
        results_df['kendalls_tau'] = kendalls_taus

        # Repeat for bottom row with Kendall's Tau
        for idx, (col1, col2, col3) in enumerate([('eta1', 'eta2', 'eta3'),
                                                  ('eta1', 'eta3', 'eta2'),
                                                  ('eta2', 'eta3', 'eta1')]):
            pivot = results_df.pivot_table(
                values='kendalls_tau',
                index=col1,
                columns=col2,
                aggfunc='mean'
            )

            sns.heatmap(pivot, annot=True, fmt='.3f', cmap='RdYlBu', ax=axes[1, idx],
                        cbar_kws={'label': "Kendall's Tau"}, vmin=0, vmax=1)
            axes[1, idx].set_title(f'{col1} vs {col2} (Kendall\'s Tau)')
            axes[1, idx].set_xlabel(f'{col2}')
            axes[1, idx].set_ylabel(f'{col1}')

        plt.tight_layout()
        plt.savefig(self.results_dir / "exploit_score_heatmaps.png", dpi=300, bbox_inches='tight')
        plt.close()

    def _create_stability_charts(self, stability_analysis: Dict[str, Any]) -> None:
        """Create stability analysis charts"""
        if 'kendalls_tau' not in stability_analysis:
            return

        fig, axes = plt.subplots(2, 3, figsize=(18, 12))

        # Extract data
        param_labels = list(stability_analysis['kendalls_tau'].keys())
        tau_values = list(stability_analysis['kendalls_tau'].values())

        # 1. Kendall's Tau bar chart
        bars = axes[0, 0].bar(range(len(param_labels)), tau_values, alpha=0.7)
        axes[0, 0].set_xlabel('Parameter Combinations')
        axes[0, 0].set_ylabel("Kendall's Tau")
        axes[0, 0].set_title("Ranking Stability by Parameter Combination")
        axes[0, 0].set_xticks(range(len(param_labels)))
        axes[0, 0].set_xticklabels(param_labels, rotation=45, ha='right')
        axes[0, 0].axhline(0.8, color='red', linestyle='--', alpha=0.5, label='High Stability Threshold')
        axes[0, 0].axhline(0.5, color='orange', linestyle='--', alpha=0.5, label='Medium Stability Threshold')
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)

        # Color bars based on stability level
        for bar, tau in zip(bars, tau_values):
            if tau > 0.8:
                bar.set_color('green')
            elif tau > 0.5:
                bar.set_color('orange')
            else:
                bar.set_color('red')

        # 2. Stability distribution pie chart
        if 'statistical_significance' in stability_analysis:
            sig_data = stability_analysis['statistical_significance']

            stability_counts = [
                sig_data.get('high_stability_count', 0),
                sig_data.get('medium_stability_count', 0),
                sig_data.get('low_stability_count', 0)
            ]
            stability_labels = ['High (τ > 0.8)', 'Medium (0.5 ≤ τ ≤ 0.8)', 'Low (τ < 0.5)']
            colors = ['green', 'orange', 'red']

            wedges, texts, autotexts = axes[0, 1].pie(stability_counts, labels=stability_labels,
                                                      autopct='%1.1f%%', colors=colors,
                                                      startangle=90)
            axes[0, 1].set_title('Stability Level Distribution')

            # Add statistics text
            stats_text = f"Mean τ: {sig_data.get('mean_tau', 0):.3f}\n"
            stats_text += f"Std τ: {sig_data.get('std_tau', 0):.3f}\n"
            stats_text += f"Overall: {sig_data.get('overall_stability', 'Unknown')}"
            axes[0, 1].text(1.3, 0.5, stats_text, transform=axes[0, 1].transAxes,
                            bbox=dict(boxstyle="round,pad=0.3", facecolor="lightgray"))

        # 3. Ranking changes analysis
        if 'ranking_changes' in stability_analysis:
            max_changes = []
            top_5_changes = []
            top_10_changes = []

            for param_key in param_labels:
                changes = stability_analysis['ranking_changes'].get(param_key, {})
                max_changes.append(changes.get('max_rank_change', 0))
                top_5_changes.append(changes.get('top_5_changes', 0))
                top_10_changes.append(changes.get('top_10_changes', 0))

            # Max rank change
            axes[0, 2].bar(range(len(param_labels)), max_changes, alpha=0.7, color='darkblue')
            axes[0, 2].set_xlabel('Parameter Combinations')
            axes[0, 2].set_ylabel('Maximum Rank Change')
            axes[0, 2].set_title('Maximum Ranking Changes')
            axes[0, 2].set_xticks(range(len(param_labels)))
            axes[0, 2].set_xticklabels(param_labels, rotation=45, ha='right')
            axes[0, 2].grid(True, alpha=0.3)

            # Top-K changes comparison
            x = np.arange(len(param_labels))
            width = 0.35

            bars1 = axes[1, 0].bar(x - width / 2, top_5_changes, width, label='Top-5 Changes', alpha=0.7)
            bars2 = axes[1, 0].bar(x + width / 2, top_10_changes, width, label='Top-10 Changes', alpha=0.7)

            axes[1, 0].set_xlabel('Parameter Combinations')
            axes[1, 0].set_ylabel('Number of Changes')
            axes[1, 0].set_title('Top-K Ranking Changes')
            axes[1, 0].set_xticks(x)
            axes[1, 0].set_xticklabels(param_labels, rotation=45, ha='right')
            axes[1, 0].legend()
            axes[1, 0].grid(True, alpha=0.3)

        # 4. Correlation metrics comparison
        if 'ranking_changes' in stability_analysis and param_labels:
            # Extract different correlation metrics
            spearman_values = []
            weighted_tau_values = []
            rbo_values = []

            for param_key in param_labels:
                # Find corresponding correlation metrics from original results
                spearman_values.append(0.9)  # Placeholder
                weighted_tau_values.append(0.85)  # Placeholder
                rbo_values.append(0.88)  # Placeholder

            axes[1, 1].plot(range(len(param_labels)), tau_values, 'o-', label="Kendall's Tau", markersize=8)
            axes[1, 1].set_xlabel('Parameter Combinations')
            axes[1, 1].set_ylabel('Correlation Value')
            axes[1, 1].set_title('Correlation Metrics Comparison')
            axes[1, 1].set_xticks(range(len(param_labels)))
            axes[1, 1].set_xticklabels(param_labels, rotation=45, ha='right')
            axes[1, 1].legend()
            axes[1, 1].grid(True, alpha=0.3)
            axes[1, 1].set_ylim(0, 1)

        # 5. Stability heatmap
        if len(param_labels) > 1:
            # Create a stability matrix based on parameter similarity
            n_params = min(len(param_labels), 10)  # Limit to 10 for readability
            stability_matrix = np.zeros((n_params, n_params))

            for i in range(n_params):
                for j in range(n_params):
                    if i == j:
                        stability_matrix[i, j] = 1.0
                    else:
                        # Simple difference-based similarity
                        stability_matrix[i, j] = 1 - abs(tau_values[i] - tau_values[j])

            sns.heatmap(stability_matrix, annot=True, fmt='.2f', cmap='RdYlGn',
                        xticklabels=param_labels[:n_params],
                        yticklabels=param_labels[:n_params],
                        ax=axes[1, 2], vmin=0, vmax=1)
            axes[1, 2].set_title('Parameter Combination Similarity')

        plt.tight_layout()
        plt.savefig(self.results_dir / "stability_analysis_comprehensive.png",
                    dpi=300, bbox_inches='tight')
        plt.close()

    # ============ Comprehensive Analysis ============

    def comprehensive_parameter_analysis(self, test_data: Union[Asset, System],
                                         analysis_level: str = "asset") -> Dict[str, Any]:
        """
        Perform comprehensive parameter analysis with all enhancements
        """
        logger.info("Starting comprehensive parameter sensitivity analysis...")
        start_time = pd.Timestamp.now()

        # 1. Set baseline
        self.set_baseline(test_data, analysis_level)

        # 2. Parameter sweep
        logger.info("Performing parameter sweeps...")
        sweep_results = self.comprehensive_parameter_sweep(test_data, analysis_level)

        # 3. Ranking stability analysis
        logger.info("Analyzing ranking stability...")
        stability_analysis = self.analyze_ranking_stability(sweep_results, test_data, analysis_level)

        # 4. Sobol sensitivity indices (if available)
        sobol_indices = {}
        if SALIB_AVAILABLE and hasattr(test_data, 'vulnerabilities') and len(test_data.vulnerabilities) > 0:
            logger.info("Calculating Sobol sensitivity indices...")
            sobol_indices = self.calculate_sobol_indices(test_data)

        # 5. Parameter interactions
        logger.info("Analyzing parameter interactions...")
        interaction_analysis = {}
        for param_group, df in sweep_results.items():
            if not df.empty:
                interaction_analysis[param_group] = self.analyze_parameter_interactions(df)

        # 6. Bootstrap confidence intervals
        logger.info("Calculating bootstrap confidence intervals...")
        bootstrap_ci = self.calculate_bootstrap_confidence_intervals(test_data)

        # 7. Score distribution analysis
        logger.info("Analyzing score distributions...")
        distribution_analysis = self.analyze_score_distributions(sweep_results)

        # 8. Compile comprehensive results
        comprehensive_results = {
            'sweep_results': sweep_results,
            'stability_analysis': stability_analysis,
            'sobol_indices': sobol_indices,
            'interaction_analysis': interaction_analysis,
            'bootstrap_ci': bootstrap_ci,
            'distribution_analysis': distribution_analysis,
            'analysis_metadata': {
                'start_time': start_time.isoformat(),
                'end_time': pd.Timestamp.now().isoformat(),
                'duration_seconds': (pd.Timestamp.now() - start_time).total_seconds(),
                'n_vulnerabilities': len(self.baseline_rankings) if self.baseline_rankings else 0,
                'analysis_level': analysis_level,
                'baseline_parameters': self.baseline_parameters
            }
        }

        # 9. Generate all visualizations
        logger.info("Creating visualizations...")
        self.create_advanced_visualizations(comprehensive_results)

        # 10. Generate academic report
        logger.info("Generating academic report...")
        self._generate_academic_report(comprehensive_results)

        # 11. Save comprehensive results
        self._save_comprehensive_results(sweep_results, stability_analysis)

        logger.info(
            f"Comprehensive analysis completed in {comprehensive_results['analysis_metadata']['duration_seconds']:.2f} seconds")

        return comprehensive_results

    def comprehensive_parameter_sweep(self, test_data: Union[Asset, System],
                                      analysis_level: str = "asset") -> Dict[str, pd.DataFrame]:
        """
        Perform comprehensive parameter sweep across all parameters
        """
        results = {}

        # Sweep δ and θ parameters
        results['delta_theta'] = self.sweep_delta_theta(test_data, analysis_level)

        # Sweep η1, η2, η3 parameters
        results['exploit_score'] = self.sweep_exploit_score_params(test_data, analysis_level)

        return results

    # ============ Helper Methods ============

    def _extract_ranking_data(self, rankings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract key ranking data for analysis"""
        if not rankings:
            return {'top_5': [], 'changes': {}}

        # Get top 5 vulnerabilities
        top_5 = [{'cve_id': r['cve_id'], 'score': r.get('priority_score', 0)}
                 for r in rankings[:5]]

        # Calculate ranking statistics
        scores = [r.get('priority_score', 0) for r in rankings]

        changes = {
            'total_vulnerabilities': len(rankings),
            'high_priority_count': len([s for s in scores if s > 7.0]),
            'medium_priority_count': len([s for s in scores if 4.0 <= s <= 7.0]),
            'low_priority_count': len([s for s in scores if s < 4.0]),
            'score_range': max(scores) - min(scores) if scores else 0,
            'score_variance': np.var(scores) if scores else 0
        }

        return {
            'top_5': top_5,
            'changes': changes
        }

    def _calculate_ranking_metrics(self, rankings: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate comprehensive ranking quality metrics"""
        if not rankings:
            return {}

        priority_scores = [r.get('priority_score', 0) for r in rankings]

        metrics = {
            'mean_priority': np.mean(priority_scores),
            'std_priority': np.std(priority_scores),
            'median_priority': np.median(priority_scores),
            'max_priority': np.max(priority_scores),
            'min_priority': np.min(priority_scores),
            'priority_range': np.max(priority_scores) - np.min(priority_scores),
            'coefficient_of_variation': np.std(priority_scores) / np.mean(priority_scores) if np.mean(
                priority_scores) > 0 else 0,
            'gini_coefficient': self._calculate_gini_coefficient(priority_scores)
        }

        return metrics

    def _calculate_gini_coefficient(self, values: List[float]) -> float:
        """Calculate Gini coefficient for inequality measurement"""
        if not values or len(values) < 2:
            return 0.0

        # Sort values
        sorted_values = sorted(values)
        n = len(sorted_values)

        # Calculate Gini
        cumsum = np.cumsum(sorted_values)
        return (2 * np.sum((np.arange(1, n + 1) * sorted_values))) / (n * cumsum[-1]) - (n + 1) / n

    def _calculate_ranking_changes(self, baseline_rankings: List[Dict],
                                   new_rankings: List[Dict]) -> Dict[str, Any]:
        """Calculate detailed ranking changes between baseline and new rankings"""
        changes = {
            'total_vulnerabilities': len(new_rankings),
            'rank_changes': {},
            'top_5_changes': 0,
            'top_10_changes': 0,
            'top_20_changes': 0,
            'max_rank_change': 0,
            'mean_rank_change': 0,
            'median_rank_change': 0
        }

        # Create ranking maps
        baseline_ranks = {rank['cve_id']: idx for idx, rank in enumerate(baseline_rankings)}
        new_ranks = {rank['cve_id']: idx for idx, rank in enumerate(new_rankings)}

        rank_changes = []

        for cve_id in set(baseline_ranks.keys()) & set(new_ranks.keys()):
            baseline_position = baseline_ranks[cve_id]
            new_position = new_ranks[cve_id]
            rank_change = baseline_position - new_position  # Positive means improved

            changes['rank_changes'][cve_id] = {
                'baseline_rank': baseline_position + 1,  # 1-indexed for display
                'new_rank': new_position + 1,
                'change': rank_change
            }

            rank_changes.append(abs(rank_change))

            # Track significant changes
            if abs(rank_change) > changes['max_rank_change']:
                changes['max_rank_change'] = abs(rank_change)

            # Track top-K movements
            if baseline_position >= 5 and new_position < 5:
                changes['top_5_changes'] += 1
            if baseline_position >= 10 and new_position < 10:
                changes['top_10_changes'] += 1
            if baseline_position >= 20 and new_position < 20:
                changes['top_20_changes'] += 1

        if rank_changes:
            changes['mean_rank_change'] = np.mean(rank_changes)
            changes['median_rank_change'] = np.median(rank_changes)

        return changes

    def _calculate_statistical_significance(self, kendalls_tau: Dict[str, float]) -> Dict[str, Any]:
        """Calculate statistical significance of ranking changes"""
        if not kendalls_tau:
            return {}

        tau_values = list(kendalls_tau.values())

        # Perform one-sample t-test against null hypothesis of tau = 0.5 (random)
        t_stat, p_value = stats.ttest_1samp(tau_values, 0.5)

        significance_analysis = {
            'mean_tau': np.mean(tau_values),
            'median_tau': np.median(tau_values),
            'std_tau': np.std(tau_values),
            'min_tau': np.min(tau_values),
            'max_tau': np.max(tau_values),
            'quartiles': {
                'Q1': np.percentile(tau_values, 25),
                'Q2': np.percentile(tau_values, 50),
                'Q3': np.percentile(tau_values, 75)
            },
            'high_stability_count': len([t for t in tau_values if t > 0.8]),
            'medium_stability_count': len([t for t in tau_values if 0.5 <= t <= 0.8]),
            'low_stability_count': len([t for t in tau_values if t < 0.5]),
            't_test': {
                't_statistic': t_stat,
                'p_value': p_value,
                'significant': p_value < self.significance_level
            }
        }

        # Categorize overall stability
        if significance_analysis['mean_tau'] > 0.8:
            significance_analysis['overall_stability'] = 'High'
        elif significance_analysis['mean_tau'] > 0.5:
            significance_analysis['overall_stability'] = 'Medium'
        else:
            significance_analysis['overall_stability'] = 'Low'

        return significance_analysis

    def analyze_ranking_stability(self, results: Dict[str, pd.DataFrame],
                                  test_data: Union[Asset, System],
                                  analysis_level: str = "asset") -> Dict[str, Any]:
        """
        Analyze ranking stability across parameter changes with comprehensive metrics
        """
        if self.baseline_rankings is None:
            logger.warning("No baseline set. Call set_baseline() first.")
            return {}

        stability_analysis = {
            'kendalls_tau': {},
            'spearman_rho': {},
            'weighted_kendalls_tau': {},
            'rank_biased_overlap': {},
            'top_k_overlap': {},
            'ranking_changes': {},
            'parameter_sensitivity': {}
        }

        # Process each parameter group
        for param_group, results_df in results.items():
            if results_df.empty:
                continue

            group_stability = {
                'tau_values': [],
                'rho_values': [],
                'weighted_tau_values': [],
                'rbo_values': []
            }

            for _, row in results_df.iterrows():
                # Update parameters based on group
                if param_group == 'delta_theta':
                    update_parameters(delta=row['delta'], theta=row['theta'])
                    param_key = f"δ={row['delta']:.1f},θ={row['theta']:.1f}"
                elif param_group == 'exploit_score':
                    update_parameters(eta1=row['eta1'], eta2=row['eta2'], eta3=row['eta3'])
                    param_key = f"η1={row['eta1']:.1f},η2={row['eta2']:.1f},η3={row['eta3']:.1f}"
                else:
                    continue

                # Get new rankings
                new_rankings = self.patch_prioritizer.rank_patches(
                    test_data,
                    analysis_level=getattr(AnalysisLevel, analysis_level.upper())
                )

                # Calculate all correlation metrics
                tau, tau_p = self.calculate_kendalls_tau(self.baseline_rankings, new_rankings)
                rho, rho_p = self.calculate_spearman_correlation(self.baseline_rankings, new_rankings)
                weighted_tau = self.calculate_weighted_kendalls_tau(self.baseline_rankings, new_rankings)
                rbo = self.calculate_rank_biased_overlap(self.baseline_rankings, new_rankings)
                top_k = self.calculate_top_k_overlap(self.baseline_rankings, new_rankings)

                # Store results
                stability_analysis['kendalls_tau'][param_key] = tau
                stability_analysis['spearman_rho'][param_key] = rho
                stability_analysis['weighted_kendalls_tau'][param_key] = weighted_tau
                stability_analysis['rank_biased_overlap'][param_key] = rbo
                stability_analysis['top_k_overlap'][param_key] = top_k

                # Calculate ranking changes
                ranking_changes = self._calculate_ranking_changes(
                    self.baseline_rankings, new_rankings
                )
                stability_analysis['ranking_changes'][param_key] = ranking_changes

                # Collect for group analysis
                group_stability['tau_values'].append(tau)
                group_stability['rho_values'].append(rho)
                group_stability['weighted_tau_values'].append(weighted_tau)
                group_stability['rbo_values'].append(rbo)

            # Calculate parameter sensitivity for this group
            stability_analysis['parameter_sensitivity'][param_group] = {
                'tau_sensitivity': np.std(group_stability['tau_values']),
                'rho_sensitivity': np.std(group_stability['rho_values']),
                'weighted_tau_sensitivity': np.std(group_stability['weighted_tau_values']),
                'rbo_sensitivity': np.std(group_stability['rbo_values'])
            }

        # Restore baseline parameters
        if self.baseline_parameters:
            update_parameters(**self.baseline_parameters)

        # Calculate statistical significance
        stability_analysis['statistical_significance'] = self._calculate_statistical_significance(
            stability_analysis['kendalls_tau']
        )

        return stability_analysis

    # ============ Output Methods ============

    def _save_delta_theta_results(self, results_df: pd.DataFrame) -> None:
        """Save δ and θ sweep results with full details"""
        # Save CSV
        output_file = self.results_dir / "delta_theta_sweep.csv"

        # Flatten nested dictionaries for CSV
        flattened_results = []
        for _, row in results_df.iterrows():
            flat_row = {
                'delta': row['delta'],
                'theta': row['theta']
            }

            # Add ranking metrics
            if isinstance(row.get('ranking_metrics'), dict):
                for key, value in row['ranking_metrics'].items():
                    flat_row[f'metric_{key}'] = value

            # Add correlation metrics
            if isinstance(row.get('correlation_metrics'), dict):
                for key, value in row['correlation_metrics'].items():
                    if isinstance(value, dict):  # Handle top_k_overlap
                        for k, v in value.items():
                            flat_row[f'correlation_{key}_top{k}'] = v
                    else:
                        flat_row[f'correlation_{key}'] = value

            flattened_results.append(flat_row)

        flattened_df = pd.DataFrame(flattened_results)
        flattened_df.to_csv(output_file, index=False)

        # Save detailed JSON
        json_file = self.results_dir / "delta_theta_sweep.json"
        with open(json_file, 'w') as f:
            json.dump(results_df.to_dict('records'), f, indent=2, default=str)

        logger.info(f"Saved δ and θ results to {output_file} and {json_file}")

    def _save_exploit_score_results(self, results_df: pd.DataFrame) -> None:
        """Save η1, η2, η3 sweep results with full details"""
        # Save CSV
        output_file = self.results_dir / "exploit_score_sweep.csv"

        # Flatten for CSV
        flattened_results = []
        for _, row in results_df.iterrows():
            flat_row = {
                'eta1': row['eta1'],
                'eta2': row['eta2'],
                'eta3': row['eta3']
            }

            # Add metrics
            if isinstance(row.get('ranking_metrics'), dict):
                for key, value in row['ranking_metrics'].items():
                    flat_row[f'metric_{key}'] = value

            if isinstance(row.get('correlation_metrics'), dict):
                for key, value in row['correlation_metrics'].items():
                    if isinstance(value, dict):
                        for k, v in value.items():
                            flat_row[f'correlation_{key}_top{k}'] = v
                    else:
                        flat_row[f'correlation_{key}'] = value

            flattened_results.append(flat_row)

        flattened_df = pd.DataFrame(flattened_results)
        flattened_df.to_csv(output_file, index=False)

        # Save detailed JSON
        json_file = self.results_dir / "exploit_score_sweep.json"
        with open(json_file, 'w') as f:
            json.dump(results_df.to_dict('records'), f, indent=2, default=str)

        logger.info(f"Saved η1, η2, η3 results to {output_file} and {json_file}")

    def _save_comprehensive_results(self, sweep_results: Dict[str, pd.DataFrame],
                                    stability_analysis: Dict[str, Any]) -> None:
        """Save comprehensive analysis results"""
        # Save stability analysis
        stability_file = self.results_dir / "stability_analysis.json"
        with open(stability_file, 'w') as f:
            json.dump(stability_analysis, f, indent=2, default=str)

        # Create comprehensive summary
        summary = {
            'analysis_timestamp': pd.Timestamp.now().isoformat(),
            'results_directory': str(self.results_dir),
            'baseline_parameters': self.baseline_parameters,
            'parameter_combinations_tested': {
                'delta_theta': len(sweep_results.get('delta_theta', [])),
                'exploit_score': len(sweep_results.get('exploit_score', []))
            },
            'stability_summary': stability_analysis.get('statistical_significance', {}),
            'files_generated': sorted([f.name for f in self.results_dir.glob('*')]),
            'analysis_settings': {
                'confidence_level': self.confidence_level,
                'n_bootstrap': self.n_bootstrap,
                'significance_level': self.significance_level
            }
        }

        summary_file = self.results_dir / "analysis_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)

        logger.info(f"Saved comprehensive analysis results to {self.results_dir}")

    def _generate_academic_report(self, results: Dict[str, Any]) -> None:
        """
        Generate LaTeX-ready academic report of sensitivity analysis
        """
        report_content = []

        # Header
        report_content.append("% Parameter Sensitivity Analysis Report")
        report_content.append(f"% Generated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_content.append("")
        report_content.append("\\section{Parameter Sensitivity Analysis}")
        report_content.append("")

        # Executive Summary
        report_content.append("\\subsection{Executive Summary}")
        if 'analysis_metadata' in results:
            meta = results['analysis_metadata']
            report_content.append(f"Analysis conducted on {meta.get('n_vulnerabilities', 'N/A')} vulnerabilities ")
            report_content.append(f"at the {meta.get('analysis_level', 'N/A')} level, ")
            report_content.append(f"completed in {meta.get('duration_seconds', 0):.1f} seconds.")
        report_content.append("")

        # Sobol Indices
        if 'sobol_indices' in results and results['sobol_indices']:
            report_content.append("\\subsection{Variance-Based Sensitivity Analysis}")
            report_content.append("")
            report_content.append("\\begin{table}[h]")
            report_content.append("\\centering")
            report_content.append("\\caption{Sobol Sensitivity Indices}")
            report_content.append("\\label{tab:sobol_indices}")
            report_content.append("\\begin{tabular}{lcc}")
            report_content.append("\\toprule")
            report_content.append("Parameter & First-Order ($S_1$) & Total-Order ($S_T$) \\\\")
            report_content.append("\\midrule")

            for param in results['sobol_indices']['first_order']:
                s1 = results['sobol_indices']['first_order'][param]
                st = results['sobol_indices']['total_order'][param]
                param_latex = param.replace('delta', '$\\delta$').replace('theta', '$\\theta$')
                param_latex = param_latex.replace('eta1', '$\\eta_1$').replace('eta2', '$\\eta_2$').replace('eta3',
                                                                                                            '$\\eta_3$')
                report_content.append(f"{param_latex} & {s1:.3f} & {st:.3f} \\\\")

            report_content.append("\\bottomrule")
            report_content.append("\\end{tabular}")
            report_content.append("\\end{table}")
            report_content.append("")

        # Stability Analysis
        if 'stability_analysis' in results and 'statistical_significance' in results['stability_analysis']:
            sig = results['stability_analysis']['statistical_significance']
            report_content.append("\\subsection{Ranking Stability Analysis}")
            report_content.append("")
            report_content.append("\\begin{itemize}")
            report_content.append(
                f"\\item Mean Kendall's $\\tau$: {sig.get('mean_tau', 0):.3f} $\\pm$ {sig.get('std_tau', 0):.3f}")
            report_content.append(f"\\item Overall Stability: {sig.get('overall_stability', 'Unknown')}")
            report_content.append(
                f"\\item High Stability Cases: {sig.get('high_stability_count', 0)} ({sig.get('high_stability_count', 0) / len(results['stability_analysis']['kendalls_tau']) * 100:.1f}\\%)")

            if 't_test' in sig:
                report_content.append(
                    f"\\item Statistical Significance: $t = {sig['t_test']['t_statistic']:.3f}$, $p = {sig['t_test']['p_value']:.4f}$")

            report_content.append("\\end{itemize}")
            report_content.append("")

        # Bootstrap Confidence Intervals
        if 'bootstrap_ci' in results:
            report_content.append("\\subsection{Bootstrap Confidence Intervals}")
            report_content.append("")
            report_content.append("\\begin{table}[h]")
            report_content.append("\\centering")
            report_content.append("\\caption{95\\% Bootstrap Confidence Intervals}")
            report_content.append("\\label{tab:bootstrap_ci}")
            report_content.append("\\begin{tabular}{lcc}")
            report_content.append("\\toprule")
            report_content.append("Metric & Mean & 95\\% CI \\\\")
            report_content.append("\\midrule")

            for metric, ci_data in results['bootstrap_ci'].items():
                metric_name = metric.replace('_', ' ').title()
                mean_val = ci_data['mean']
                ci_lower = ci_data['ci_lower']
                ci_upper = ci_data['ci_upper']
                report_content.append(f"{metric_name} & {mean_val:.3f} & [{ci_lower:.3f}, {ci_upper:.3f}] \\\\")

            report_content.append("\\bottomrule")
            report_content.append("\\end{tabular}")
            report_content.append("\\end{table}")
            report_content.append("")

        # Parameter Interactions
        if 'interaction_analysis' in results:
            report_content.append("\\subsection{Parameter Interactions}")

            for param_group, interactions in results['interaction_analysis'].items():
                if 'polynomial_regression' in interactions:
                    poly = interactions['polynomial_regression']
                    report_content.append(f"\\subsubsection{{{param_group.replace('_', ' ').title()}}}")
                    report_content.append(f"Polynomial regression $R^2 = {poly.get('r2_score', 0):.3f}$")
                    report_content.append("")

        # Save report
        report_file = self.results_dir / "sensitivity_analysis_report.tex"
        with open(report_file, 'w') as f:
            f.write('\n'.join(report_content))

        # Also save as markdown for easier reading
        md_content = []
        md_content.append("# Parameter Sensitivity Analysis Report")
        md_content.append(f"Generated: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md_content.append("")

        if 'analysis_metadata' in results:
            meta = results['analysis_metadata']
            md_content.append("## Analysis Summary")
            md_content.append(f"- Vulnerabilities analyzed: {meta.get('n_vulnerabilities', 'N/A')}")
            md_content.append(f"- Analysis level: {meta.get('analysis_level', 'N/A')}")
            md_content.append(f"- Duration: {meta.get('duration_seconds', 0):.1f} seconds")
            md_content.append("")

        if 'sobol_indices' in results and results['sobol_indices']:
            md_content.append("## Sobol Sensitivity Indices")
            md_content.append("")
            md_content.append("| Parameter | First-Order (S₁) | Total-Order (Sₜ) |")
            md_content.append("|-----------|------------------|------------------|")

            for param in results['sobol_indices']['first_order']:
                s1 = results['sobol_indices']['first_order'][param]
                st = results['sobol_indices']['total_order'][param]
                md_content.append(f"| {param} | {s1:.3f} | {st:.3f} |")
            md_content.append("")

        md_file = self.results_dir / "sensitivity_analysis_report.md"
        with open(md_file, 'w') as f:
            f.write('\n'.join(md_content))

        logger.info(f"Generated academic reports: {report_file} and {md_file}")


# ============ Convenience Functions ============

def analyze_parameter_sensitivity(test_data: Union[Asset, System],
                                  analysis_level: str = "asset",
                                  parameter_group: str = "all") -> Dict[str, Any]:
    """
    Quick parameter sensitivity analysis with comprehensive metrics

    Args:
        test_data: Asset or System object for testing
        analysis_level: "asset" or "system"
        parameter_group: "delta_theta", "exploit_score", or "all"

    Returns:
        Dictionary with comprehensive parameter sensitivity results
    """
    analyzer = ParameterSensitivityAnalyzer()

    if parameter_group == "all":
        return analyzer.comprehensive_parameter_analysis(test_data, analysis_level)
    else:
        analyzer.set_baseline(test_data, analysis_level)

        if parameter_group == "delta_theta":
            results = {"delta_theta": analyzer.sweep_delta_theta(test_data, analysis_level)}
        elif parameter_group == "exploit_score":
            results = {"exploit_score": analyzer.sweep_exploit_score_params(test_data, analysis_level)}
        else:
            raise ValueError(f"Unknown parameter group: {parameter_group}")

        # Analyze stability
        stability = analyzer.analyze_ranking_stability(results, test_data, analysis_level)

        # Generate visualizations
        analyzer.generate_sensitivity_heatmaps(results)

        return {
            'sweep_results': results,
            'stability_analysis': stability
        }


if __name__ == "__main__":
    # Example usage
    logger.info("Parameter sensitivity analysis module loaded successfully")