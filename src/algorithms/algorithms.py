"""
Formal Algorithms for VulRG/PatchRank
"""

import logging
from typing import Dict, List, Tuple, Set, Any, Optional
import networkx as nx
from dataclasses import dataclass
import numpy as np

try:
    from ..core.graph_utils import GraphUtils
    from ..core.exploit_score import ExploitScoreCalculator
    from ..core.mitigation_factor import MitigationFactorCalculator
    from ..conf import get_config
except ImportError:
    # Fallback for when running from project root
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from core.graph_utils import GraphUtils
    from core.exploit_score import ExploitScoreCalculator
    from core.mitigation_factor import MitigationFactorCalculator
    from conf import get_config

logger = logging.getLogger(__name__)


@dataclass 
class PathRiskResult:
    """Result from Algorithm 2: k-shortest path risk calculation"""
    source_asset: str
    target_asset: str
    path: List[str]
    probability: float
    risk: float
    impact: float


@dataclass
class PatchUtilityResult:
    """Result for individual patch utility calculation"""
    vulnerability_id: str
    utility: float
    risk_reduction: float
    cost: float
    time_required: float


@dataclass
class OptimalPatchSet:
    """Result from Algorithm 3: resource-constrained patch ranking"""
    selected_patches: List[str]
    total_utility: float
    total_cost: float
    total_time: float
    risk_reduction: float


class Algorithm2_KShortestPathRisk:
    """
    Algorithm 2: k-Shortest Path Risk Calculation
    
    Implements the formal algorithm from EquationReferences.md:
    Input: Directed attack graph D, vulnerable asset set A_h, integer k
    Output: List of (a_s, a_h, Paths, Probabilities)
    """
    
    def __init__(self, graph: nx.DiGraph = None):
        """
        Initialize Algorithm 2 with attack graph
        
        Args:
            graph: Directed attack graph D
        """
        self.config = get_config()
        self.graph = graph
        self.graph_utils = GraphUtils()
        self.exploit_calculator = ExploitScoreCalculator()
        self.mitigation_calculator = MitigationFactorCalculator()
        
        if graph:
            self.graph_utils.set_graph(graph)
    
    def execute(self, vulnerable_assets: List[str], 
                source_assets: List[str] = None,
                k: int = None) -> List[PathRiskResult]:
        """
        Execute Algorithm 2: k-shortest path risk calculation
        
        Args:
            vulnerable_assets: Vulnerable asset set A_h
            source_assets: Source asset set (if None, uses all assets)
            k: Number of shortest paths (if None, uses config value)
            
        Returns:
            List of PathRiskResult objects
        """
        if not self.graph:
            raise ValueError("Attack graph D not set")
            
        if k is None:
            k = self.config.risk_calculation.k_shortest_paths
            
        if source_assets is None:
            source_assets = list(self.graph.nodes)
        
        logger.info(f"Executing Algorithm 2: {len(vulnerable_assets)} targets, "
                   f"{len(source_assets)} sources, k={k}")
        
        # Algorithm 2 implementation
        results = []  # Step 1: Initialize results ← []
        
        # Step 2: For each asset a_h in A_h:
        for target_asset in vulnerable_assets:
            if target_asset not in self.graph.nodes:
                logger.warning(f"Target asset {target_asset} not in graph")
                continue
                
            # Step 3: For each source asset a_s:
            for source_asset in source_assets:
                if source_asset == target_asset or source_asset not in self.graph.nodes:
                    continue
                
                # Step 4: P ← k-shortest paths from a_s to a_h in D
                paths = self.graph_utils.k_shortest_paths(source_asset, target_asset, k)
                
                # Step 5: For each path p in P:
                for path_info in paths:
                    # Step 6: prob ← ∏ ( EL(e) * MF(e) ) for edges e in p
                    probability = self._calculate_path_probability(path_info.edges)
                    
                    # Step 7: risk ← prob * Impact(p)  
                    impact = self._calculate_path_impact(path_info.edges)
                    risk = probability * impact
                    
                    # Step 8: results.append((a_s, a_h, p, prob, risk))
                    result = PathRiskResult(
                        source_asset=source_asset,
                        target_asset=target_asset,
                        path=path_info.path,
                        probability=probability,
                        risk=risk,
                        impact=impact
                    )
                    results.append(result)
        
        # Step 9: Return results
        logger.info(f"Algorithm 2 complete: {len(results)} path risk results")
        return results
    
    def _calculate_path_probability(self, edges: List[Tuple[str, str]]) -> float:
        """
        Calculate path probability: prob ← ∏ ( EL(e) * MF(e) ) for edges e in path
        Implements Step 6 of Algorithm 2, integrating with existing risk calculation system
        """
        probability = 1.0
        
        for edge in edges:
            if self.graph.has_edge(*edge):
                edge_data = self.graph[edge[0]][edge[1]]
                
                # Get exploit likelihood EL(e) - use CORRECTED Equation 7 calculation
                if 'vulnerability' in edge_data:
                    # Use vulnerability-specific exploit likelihood with CORRECTED Equation 7
                    vulnerability = edge_data['vulnerability']
                    
                    # Create a mock vulnerability object for EL calculation
                    try:
                        from ..core.models import Vulnerability
                        from ..core.risk_calculator import RiskCalculator
                        
                        # Create vulnerability object if needed
                        if not isinstance(vulnerability, Vulnerability):
                            vuln_obj = Vulnerability(
                                cve_id=vulnerability.get('cve_id', 'unknown'),
                                cvss=vulnerability.get('cvss', 5.0),
                                epss=vulnerability.get('epss', 0.5),
                                likelihood=vulnerability.get('likelihood', 5.0),
                                impact=vulnerability.get('impact', 5.0),
                                scope_changed=vulnerability.get('scope_changed', False),
                                ransomware=vulnerability.get('ransomware', 0.0)
                            )
                        else:
                            vuln_obj = vulnerability
                        
                        # Use corrected EL calculation from risk_calculator
                        risk_calc = RiskCalculator()
                        exploit_likelihood = risk_calc.calculate_exploit_likelihood(
                            vuln_obj, 
                            edge_data.get('asset', {})
                        )
                        
                    except Exception as e:
                        logger.warning(f"Failed to calculate EL for edge {edge}: {e}")
                        # Fallback to continuous ExploitScore only
                        exploit_likelihood = self.exploit_calculator.calculate_exploit_score(
                            vulnerability.get('cve_id', 'unknown'),
                            edge_data.get('asset', {}),
                            vulnerability
                        )
                else:
                    # Use stored exploit likelihood or default
                    exploit_likelihood = edge_data.get('exploit_likelihood', 0.5)
                
                # Get mitigation factor MF(e) - integrate with existing mitigation system
                if 'mitigation_data' in edge_data:
                    # Calculate mitigation factor using existing system
                    mitigation_factor = self.mitigation_calculator.compute_mitigation_factor(edge_data)
                else:
                    # Use stored mitigation factor or default
                    mitigation_factor = edge_data.get('mitigation_factor', 1.0)
                
                # Multiply: EL(e) * MF(e) per Algorithm 2 Step 6
                edge_probability = exploit_likelihood * mitigation_factor
                probability *= edge_probability
            else:
                logger.warning(f"Edge {edge} not found in graph")
                probability *= 0.1  # Default low probability for missing edges
        
        return probability
    
    def _calculate_path_impact(self, edges: List[Tuple[str, str]]) -> float:
        """
        Calculate path impact: Impact(p)
        Implements impact aggregation for Step 7 of Algorithm 2
        """
        total_impact = 0.0
        
        for edge in edges:
            if self.graph.has_edge(*edge):
                edge_data = self.graph[edge[0]][edge[1]]
                impact = edge_data.get('impact_score', 1.0)
                total_impact += impact
            else:
                total_impact += 0.5  # Default impact
        
        return total_impact
    
    def validate_against_baseline(self, vulnerable_assets: List[str]) -> Dict[str, Any]:
        """
        Validate Algorithm 2 against baseline shortest path calculation
        For regression testing and performance comparison
        """
        # Execute with k=1 (shortest path only)
        k1_results = self.execute(vulnerable_assets, k=1)
        
        # Execute with k=3 (multiple paths)
        k3_results = self.execute(vulnerable_assets, k=3)
        
        # Compare results
        validation = {
            'k1_total_risk': sum(r.risk for r in k1_results),
            'k3_total_risk': sum(r.risk for r in k3_results),
            'k1_path_count': len(k1_results),
            'k3_path_count': len(k3_results),
            'risk_increase_ratio': 0.0,
            'path_coverage_increase': len(k3_results) / max(len(k1_results), 1)
        }
        
        if validation['k1_total_risk'] > 0:
            validation['risk_increase_ratio'] = (
                validation['k3_total_risk'] / validation['k1_total_risk']
            )
        
        return validation


class Algorithm3_ResourceConstrainedPatchRanking:
    """
    Algorithm 3: Resource-Constrained Patch Ranking
    
    Implements the formal algorithm from EquationReferences.md:
    Input: Vulnerability set V, Budget, AvailableTime
    Output: Optimal patch set S*
    """
    
    def __init__(self, vulnerability_data: List[Dict[str, Any]] = None):
        """
        Initialize Algorithm 3 with vulnerability data
        
        Args:
            vulnerability_data: List of vulnerability dictionaries with cost/time/risk data
        """
        self.config = get_config()
        self.vulnerability_data = vulnerability_data or []
        self.algorithm2 = None  # Will be set when needed for risk calculations
    
    def execute(self, vulnerabilities: List[str], 
                budget: float, 
                available_time: float,
                risk_calculator = None,
                vulnerability_data: List[Dict[str, Any]] = None) -> OptimalPatchSet:
        """
        Execute Algorithm 3: Resource-constrained patch ranking
        
        Args:
            vulnerabilities: Vulnerability set V
            budget: Budget constraint
            available_time: AvailableTime constraint  
            risk_calculator: Risk calculator for R_initial and R_patched calculations
            
        Returns:
            OptimalPatchSet with optimal patch selection
        """
        logger.info(f"Executing Algorithm 3: {len(vulnerabilities)} vulnerabilities, "
                   f"budget={budget}, time={available_time}")
        
        # Update vulnerability data if provided
        if vulnerability_data:
            self.vulnerability_data = vulnerability_data
            logger.info(f"Updated vulnerability data with {len(vulnerability_data)} entries")
        
        # Step 1: For each v in V:
        utilities = []
        for vuln_id in vulnerabilities:
            # Step 2: utility(v) ← (R_initial - R_patched(v)) / Cost(v)
            utility_result = self._calculate_patch_utility(vuln_id, risk_calculator)
            utilities.append(utility_result)
        
        # Step 3: Solve knapsack
        # Step 4: Maximize Σ utility(v) over S ⊆ V
        # Step 5: Subject to Σ Cost(v) ≤ Budget, Σ Time(v) ≤ AvailableTime
        optimal_patches = self._solve_knapsack_optimization(
            utilities, budget, available_time
        )
        
        # Step 6: Return optimal patch set S*
        return optimal_patches
    
    def _calculate_patch_utility(self, vulnerability_id: str, 
                               risk_calculator = None) -> PatchUtilityResult:
        """
        Calculate patch utility: utility(v) ← (R_initial - R_patched(v)) / Cost(v)
        Implements Steps 1-2 of Algorithm 3
        """
        # Get vulnerability data
        vuln_data = self._get_vulnerability_data(vulnerability_id)
        cost = vuln_data.get('cost', 1.0)
        time_required = vuln_data.get('time', 1.0)
        
        # Calculate risk reduction
        if risk_calculator:
            r_initial = self._calculate_initial_risk(vulnerability_id, risk_calculator)
            r_patched = self._calculate_patched_risk(vulnerability_id, risk_calculator) 
            risk_reduction = r_initial - r_patched
        else:
            # Use simplified risk reduction estimate
            cvss_score = vuln_data.get('cvss_score', 5.0)
            risk_reduction = cvss_score * vuln_data.get('exploit_score', 0.5)
        
        # Calculate utility: (R_initial - R_patched(v)) / Cost(v)
        utility = risk_reduction / max(cost, 0.01)  # Avoid division by zero
        
        return PatchUtilityResult(
            vulnerability_id=vulnerability_id,
            utility=utility,
            risk_reduction=risk_reduction,
            cost=cost,
            time_required=time_required
        )
    
    def _solve_knapsack_optimization(self, 
                                   utilities: List[PatchUtilityResult],
                                   budget: float,
                                   available_time: float) -> OptimalPatchSet:
        """
        Solve knapsack optimization problem
        Implements Steps 3-6 of Algorithm 3
        """
        # Convert to knapsack problem
        items = []
        for i, util in enumerate(utilities):
            items.append({
                'id': i,
                'vulnerability': util.vulnerability_id,
                'utility': util.utility,
                'cost': util.cost,
                'time': util.time_required,
                'risk_reduction': util.risk_reduction
            })
        
        # Sort by utility (greedy approximation for dual constraint knapsack)
        items.sort(key=lambda x: x['utility'], reverse=True)
        
        # Greedy selection with dual constraints
        selected = []
        total_cost = 0.0
        total_time = 0.0
        total_utility = 0.0
        total_risk_reduction = 0.0
        
        for item in items:
            # Check if adding this item violates constraints
            if (total_cost + item['cost'] <= budget and 
                total_time + item['time'] <= available_time):
                
                selected.append(item['vulnerability'])
                total_cost += item['cost']
                total_time += item['time'] 
                total_utility += item['utility']
                total_risk_reduction += item['risk_reduction']
        
        return OptimalPatchSet(
            selected_patches=selected,
            total_utility=total_utility,
            total_cost=total_cost,
            total_time=total_time,
            risk_reduction=total_risk_reduction
        )
    
    def _get_vulnerability_data(self, vulnerability_id: str) -> Dict[str, Any]:
        """Get vulnerability data for utility calculation"""
        for vuln in self.vulnerability_data:
            if vuln.get('id') == vulnerability_id:
                return vuln
        
        # Return default data if not found
        logger.warning(f"Vulnerability data not found for {vulnerability_id}, using defaults")
        return {
            'id': vulnerability_id,
            'cost': 1.0,
            'time': 1.0,
            'cvss_score': 5.0,
            'exploit_score': 0.5
        }
    
    def _calculate_initial_risk(self, vulnerability_id: str, risk_calculator) -> float:
        """Calculate initial risk R_initial using the CORRECTED risk calculation system"""
        if not risk_calculator:
            return 5.0  # Default fallback
            
        # Get vulnerability data
        vuln_data = self._get_vulnerability_data(vulnerability_id)
        
        try:
            # Create a vulnerability object for CORRECTED risk calculation
            from ..core.models import Vulnerability
            
            vulnerability = Vulnerability(
                cve_id=vulnerability_id,
                cvss=vuln_data.get('cvss_score', 5.0),
                epss=vuln_data.get('epss', 0.5),
                likelihood=vuln_data.get('likelihood', 5.0),
                impact=vuln_data.get('impact', 5.0),
                scope_changed=vuln_data.get('scope_changed', False),
                ransomware=vuln_data.get('ransomware', 0.0)
            )
            
            # Use CORRECTED total risk calculation (R = R_direct + R_indirect + R_network)
            if hasattr(risk_calculator, 'calculate_total_risk'):
                # Use new total risk calculation
                risk = risk_calculator.calculate_total_risk(
                    vulnerability,
                    asset=vuln_data.get('asset', {})
                )
            else:
                # Fallback to vulnerability risk calculation
                risk = risk_calculator.calculate_vulnerability_risk(vulnerability)
            
            return risk
            
        except Exception as e:
            logger.warning(f"Failed to calculate initial risk for {vulnerability_id}: {e}")
            # Enhanced fallback calculation using corrected EL
            try:
                # Try to calculate exploit likelihood using corrected method
                vulnerability = Vulnerability(
                    cve_id=vulnerability_id,
                    cvss=vuln_data.get('cvss_score', 5.0),
                    epss=vuln_data.get('epss', 0.5),
                    likelihood=vuln_data.get('likelihood', 5.0),
                    impact=vuln_data.get('impact', 5.0),
                    scope_changed=vuln_data.get('scope_changed', False),
                    ransomware=vuln_data.get('ransomware', 0.0)
                )
                el = risk_calculator.calculate_exploit_likelihood(vulnerability, vuln_data.get('asset', {}))
                direct_risk = risk_calculator.calculate_direct_risk(el, vulnerability.impact)
                return direct_risk
            except:
                # Ultimate fallback
                cvss_score = vuln_data.get('cvss_score', 5.0)
                exploit_score = vuln_data.get('exploit_score', 0.5)
                return cvss_score * exploit_score
    
    def _calculate_patched_risk(self, vulnerability_id: str, risk_calculator) -> float:
        """Calculate risk after patching R_patched(v)"""
        # After patching, vulnerability is eliminated, so risk becomes 0
        # This follows the paper's assumption that patches fully remediate vulnerabilities
        return 0.0


class AlgorithmValidator:
    """Validator for algorithm correctness and performance"""
    
    def __init__(self):
        self.config = get_config()
    
    def validate_algorithm2(self, graph: nx.DiGraph, 
                          test_cases: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate Algorithm 2 against test cases
        
        Args:
            graph: Test attack graph
            test_cases: List of test case specifications
            
        Returns:
            Validation results
        """
        algorithm2 = Algorithm2_KShortestPathRisk(graph)
        validation_results = {
            'test_cases_passed': 0,
            'total_test_cases': len(test_cases),
            'detailed_results': []
        }
        
        for i, test_case in enumerate(test_cases):
            try:
                # Execute algorithm
                results = algorithm2.execute(
                    test_case['vulnerable_assets'],
                    test_case.get('source_assets'),
                    test_case.get('k', 3)
                )
                
                # Validate expected results
                expected_paths = test_case.get('expected_min_paths', 0)
                expected_risk_range = test_case.get('expected_risk_range', (0.0, float('inf')))
                
                actual_paths = len(results)
                total_risk = sum(r.risk for r in results)
                
                test_passed = (
                    actual_paths >= expected_paths and
                    expected_risk_range[0] <= total_risk <= expected_risk_range[1]
                )
                
                if test_passed:
                    validation_results['test_cases_passed'] += 1
                
                validation_results['detailed_results'].append({
                    'test_case': i,
                    'passed': test_passed,
                    'expected_paths': expected_paths,
                    'actual_paths': actual_paths,
                    'expected_risk_range': expected_risk_range,
                    'actual_risk': total_risk
                })
                
            except Exception as e:
                logger.error(f"Test case {i} failed with error: {e}")
                validation_results['detailed_results'].append({
                    'test_case': i,
                    'passed': False,
                    'error': str(e)
                })
        
        validation_results['success_rate'] = (
            validation_results['test_cases_passed'] / len(test_cases)
            if test_cases else 0.0
        )
        
        return validation_results
    
    def validate_algorithm3(self, test_cases: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate Algorithm 3 against test cases
        
        Args:
            test_cases: List of test case specifications
            
        Returns:
            Validation results  
        """
        validation_results = {
            'test_cases_passed': 0,
            'total_test_cases': len(test_cases),
            'detailed_results': []
        }
        
        for i, test_case in enumerate(test_cases):
            try:
                algorithm3 = Algorithm3_ResourceConstrainedPatchRanking(
                    test_case.get('vulnerability_data', [])
                )
                
                result = algorithm3.execute(
                    test_case['vulnerabilities'],
                    test_case['budget'],
                    test_case['available_time']
                )
                
                # Validate constraints
                cost_satisfied = result.total_cost <= test_case['budget']
                time_satisfied = result.total_time <= test_case['available_time']
                min_patches = test_case.get('expected_min_patches', 0)
                patches_satisfied = len(result.selected_patches) >= min_patches
                
                test_passed = cost_satisfied and time_satisfied and patches_satisfied
                
                if test_passed:
                    validation_results['test_cases_passed'] += 1
                
                validation_results['detailed_results'].append({
                    'test_case': i,
                    'passed': test_passed,
                    'cost_satisfied': cost_satisfied,
                    'time_satisfied': time_satisfied,
                    'patches_satisfied': patches_satisfied,
                    'selected_patches': len(result.selected_patches),
                    'total_utility': result.total_utility
                })
                
            except Exception as e:
                logger.error(f"Test case {i} failed with error: {e}")
                validation_results['detailed_results'].append({
                    'test_case': i,
                    'passed': False,
                    'error': str(e)
                })
        
        validation_results['success_rate'] = (
            validation_results['test_cases_passed'] / len(test_cases)
            if test_cases else 0.0
        )
        
        return validation_results


# Convenience functions for direct algorithm execution
def execute_algorithm2(graph: nx.DiGraph, vulnerable_assets: List[str], 
                      k: int = 3) -> List[PathRiskResult]:
    """Execute Algorithm 2 directly"""
    algorithm = Algorithm2_KShortestPathRisk(graph)
    return algorithm.execute(vulnerable_assets, k=k)


def execute_algorithm3(vulnerabilities: List[str], vulnerability_data: List[Dict[str, Any]],
                      budget: float, available_time: float) -> OptimalPatchSet:
    """Execute Algorithm 3 directly"""
    algorithm = Algorithm3_ResourceConstrainedPatchRanking(vulnerability_data)
    return algorithm.execute(vulnerabilities, budget, available_time)