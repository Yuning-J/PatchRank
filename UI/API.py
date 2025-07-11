from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import sys
import json
import numpy as np
import copy

try:
    import torch

    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

# Add src to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src_dir = os.path.join(parent_dir, 'src')
sys.path.append(src_dir)

from core.data_loader import DataLoader
from core.risk_calculator import RiskCalculator
from core.patch_prioritizer import PatchPrioritizer
from core.graph_processor import GraphProcessor
from core.dependency_calculator import DependencyCalculator
from core.models import AnalysisLevel, Asset, System
import uuid

app = Flask(__name__)
CORS(app)

# Store patch sessions in memory (in production, use a database)
patch_sessions = {}


def convert_to_json_serializable(obj):
    """Convert numpy/torch types to JSON serializable types"""
    # Handle numpy types
    if isinstance(obj, (np.integer, np.floating, np.number)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, np.bool_):
        return bool(obj)

    # Handle torch types
    elif HAS_TORCH and isinstance(obj, torch.Tensor):
        return obj.detach().cpu().numpy().tolist() if obj.dim() > 0 else obj.item()

    # Handle other numeric types that might have item() method
    elif hasattr(obj, 'item') and callable(getattr(obj, 'item')):
        try:
            return obj.item()
        except:
            pass

    # Handle collections
    elif isinstance(obj, list):
        return [convert_to_json_serializable(item) for item in obj]
    elif isinstance(obj, tuple):
        return [convert_to_json_serializable(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: convert_to_json_serializable(value) for key, value in obj.items()}

    # Handle other types that might be numeric
    else:
        # Check if it's a float32 or similar type by string representation
        type_name = type(obj).__name__
        if 'float32' in type_name or 'float64' in type_name:
            return float(obj)
        elif 'int32' in type_name or 'int64' in type_name:
            return int(obj)

        # Try to convert to float if it looks like a number
        try:
            if hasattr(obj, '__float__'):
                return float(obj)
        except:
            pass
        return obj


def calculate_system_risk_comprehensive(system, config_file):
    """Calculate system risk using the exact same process as analyze endpoint"""
    try:
        # Extract scenario ID from filename
        scenario_id = config_file.split('_')[1].split('.')[0] if '_' in config_file else 'default'

        # Initialize components
        risk_calc = RiskCalculator()
        graph_processor = GraphProcessor()
        asset_data_path = os.path.join(parent_dir, 'data', 'asset_data')
        dependency_calc = DependencyCalculator(asset_data_path)

        # Generate dependency analysis
        centrality_dict = dependency_calc.generate_dependence(system, scenario_id)
        sys_comp_centrality = centrality_dict['component_centrality']

        # Process each asset
        for asset in system.assets:
            G, data_obj = graph_processor.generate_sub_graph(asset)
            _, _, _, total_propagated_risk = risk_calc.calculate_asset_risk(asset, data_obj)
            asset.total_propagated_risk = total_propagated_risk
            print(f"  Asset {asset.name} calculated risk: {total_propagated_risk}")

        # Recalculate asset criticality based on centrality
        asset_centrality = centrality_dict.get('asset_centrality', {})
        updated_criticality, final_criticality = risk_calc.recalculate_asset_criticality(
            system.assets, asset_centrality
        )

        # Update asset criticality values
        for asset in system.assets:
            asset_id = str(asset.asset_id)
            asset.updated_criticality = updated_criticality.get(asset_id, asset.criticality_level)
            asset.final_criticality = final_criticality.get(asset_id, asset.criticality_level)

        # Generate network graph
        main_graph = graph_processor.generate_network_graph(system)

        # Calculate system-level risk
        system_risk = risk_calc.calculate_system_risk(
            main_graph, system, sys_comp_centrality,
            criticality_threshold=6, graph_processor=graph_processor
        )

        print(f"  System risk calculated: {system_risk}")

        # If system risk is 0, use a fallback calculation
        if system_risk == 0:
            fallback_risk = 0.0
            for asset in system.assets:
                if hasattr(asset, 'total_propagated_risk') and hasattr(asset, 'updated_criticality'):
                    asset_contribution = asset.total_propagated_risk * (asset.updated_criticality + 0.1)
                    fallback_risk += asset_contribution

            if fallback_risk == 0:
                for asset in system.assets:
                    for component in asset.components:
                        for vulnerability in component.vulnerabilities:
                            fallback_risk += vulnerability.cvss * 0.1

            system_risk = fallback_risk
            print(f"  Using fallback system risk: {system_risk}")

        return system_risk

    except Exception as e:
        print(f"ERROR in calculate_system_risk_comprehensive: {e}")
        import traceback
        traceback.print_exc()
        return 0.0


@app.route('/api/configs', methods=['GET'])
def get_configs():
    asset_dir = os.path.join(parent_dir, 'data', 'asset_withVul_data')
    system_dir = os.path.join(parent_dir, 'data', 'asset_data')

    asset_files = []
    system_files = []

    # Check all JSON files in asset_withVul_data directory
    for filename in os.listdir(asset_dir):
        if filename.endswith('.json'):
            file_path = os.path.join(asset_dir, filename)
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    # Asset-level files have 'components' at root level
                    # System-level files have 'Assets' array at root level
                    if 'components' in data and 'Assets' not in data:
                        asset_files.append(filename)
                    elif 'Assets' in data:
                        system_files.append(filename)
                    else:
                        # Default to asset if structure is unclear
                        asset_files.append(filename)
            except Exception as e:
                print(f"Error reading {filename}: {e}")
                # Default to asset if there's an error
                asset_files.append(filename)

    # Check all JSON files in asset_data directory (these are typically system-level)
    # Exclude dependency files and non-configuration files
    excluded_files = {
        'inter_dependencies.json',
        'enterprise_system_input.json'  # This appears to be a dependency/input file, not a system config
    }

    for filename in os.listdir(system_dir):
        if filename.endswith('.json') and filename not in excluded_files:
            file_path = os.path.join(system_dir, filename)
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    # Files in asset_data directory are typically system-level
                    system_files.append(filename)
            except Exception as e:
                print(f"Error reading {filename}: {e}")
                # Default to system if there's an error
                system_files.append(filename)

    return jsonify({
        'asset': asset_files,
        'system': system_files
    })


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Run asset-level or system-level analysis and patch ranking using the new core modules"""
    try:
        data = request.json
        data_file = data.get('file')
        level = data.get('level', 'asset')
        if not data_file:
            return jsonify({'error': 'No data file provided'}), 400

        # Initialize components
        data_path = os.path.join(parent_dir, 'data', 'asset_withVul_data')
        loader = DataLoader(data_path)
        risk_calc = RiskCalculator()
        prioritizer = PatchPrioritizer()
        graph_processor = GraphProcessor()

        if level == 'system':
            # System-level analysis - system files are also in asset_withVul_data
            system_data_path = os.path.join(parent_dir, 'data', 'asset_withVul_data')
            loader = DataLoader(system_data_path)
            data = loader.load_data(data_file)

            # Ensure we have a System object
            if not isinstance(data, System):
                return jsonify({'error': f'File {data_file} is not a valid system-level configuration'}), 400

            system = data  # Now we know it's a System

            # Use our comprehensive risk calculation
            system_risk = calculate_system_risk_comprehensive(system, data_file)

            # Rank patches
            patches = prioritizer.rank_patches(system, AnalysisLevel.SYSTEM, system_risk,
                                               main_graph=None, comp_centrality_data={})

            # Convert patches to frontend-compatible format
            formatted_patches = []
            for patch in patches[:10]:  # Return top 10 patches
                # Handle dictionary format from new patch prioritizer
                if isinstance(patch, dict):
                    formatted_patch = {
                        'id': patch.get('cve_id', ''),
                        'cve_id': patch.get('cve_id', ''),
                        'risk_reduction': patch.get('final_score', patch.get('risk_reduction', 0)),
                        'patched_risk': patch.get('patched_system_risk', 0),
                        'cvss': patch.get('cvss_score', 0),
                        'exploit': bool(patch.get('has_exploit', False)),
                        'component_id': patch.get('component_id', ''),
                        'asset_name': patch.get('asset_id', ''),
                        'likelihood': 0,  # Not provided in new format
                        'impact': 0,  # Not provided in new format
                        'scopeChanged': False,  # Not provided in new format
                        'ransomWare': patch.get('is_ransomware', False),
                        'epss': patch.get('epss_score', 0)
                    }
                else:
                    # Fallback for tuple format
                    formatted_patch = {
                        'id': patch[0],  # CVE ID
                        'cve_id': patch[0],
                        'risk_reduction': patch[1],
                        'patched_risk': patch[2],
                        'cvss': patch[3],
                        'exploit': patch[4],
                        'component_id': patch[5],
                        'asset_name': patch[6],
                        'likelihood': patch[7] if len(patch) > 7 else 0,
                        'impact': patch[8] if len(patch) > 8 else 0,
                        'scopeChanged': patch[9] if len(patch) > 9 else False,
                        'ransomWare': patch[10] if len(patch) > 10 else False,
                        'epss': patch[11] if len(patch) > 11 else 0
                    }
                formatted_patches.append(formatted_patch)

            # Calculate vulnerability statistics for system-level analysis
            all_vulnerabilities = []
            for asset in system.assets:
                for component in asset.components:
                    for vulnerability in component.vulnerabilities:
                        all_vulnerabilities.append(vulnerability)

            # Calculate statistics
            total_vulnerabilities = len(all_vulnerabilities)
            exploitable_vulnerabilities = sum(1 for v in all_vulnerabilities if v.exploit)
            critical_high_vulnerabilities = sum(1 for v in all_vulnerabilities if v.cvss >= 7.0)

            # CVSS distribution
            cvss_distribution = [0, 0, 0]  # Low, Medium, High
            for v in all_vulnerabilities:
                if v.cvss >= 7.0:
                    cvss_distribution[2] += 1  # High
                elif v.cvss >= 4.0:
                    cvss_distribution[1] += 1  # Medium
                else:
                    cvss_distribution[0] += 1  # Low

            # Location distribution (by asset)
            location_distribution = []
            for asset in system.assets:
                asset_vuln_count = sum(len(comp.vulnerabilities) for comp in asset.components)
                if asset_vuln_count > 0:
                    location_distribution.append(asset_vuln_count)

            # Pad to at least 3 elements
            while len(location_distribution) < 3:
                location_distribution.append(0)

            # Format asset risks for frontend
            formatted_asset_risks = []
            for asset in system.assets:
                formatted_asset_risks.append({
                    'id': asset.asset_id,
                    'name': asset.name,
                    'criticality': asset.final_criticality if hasattr(asset,
                                                                      'final_criticality') else asset.criticality_level,
                    'risk': asset.total_propagated_risk if hasattr(asset, 'total_propagated_risk') else 0.0,
                    'originalRisk': asset.total_propagated_risk if hasattr(asset, 'total_propagated_risk') else 0.0
                    # For virtual patching
                })

            result = {
                'system_risk': system_risk,
                'total_risk': system_risk,  # Add for frontend compatibility
                'risk': system_risk,  # CRITICAL FIX: Add 'risk' field for consistency with patch endpoints
                'patches': formatted_patches,
                'level': 'system',
                'config_file': data_file,
                'asset_risks': formatted_asset_risks,  # Add asset risks for frontend
                'vulnerability_stats': {
                    'total_vulnerabilities': total_vulnerabilities,
                    'exploitable_vulnerabilities': exploitable_vulnerabilities,
                    'critical_high_vulnerabilities': critical_high_vulnerabilities,
                    'cvss_distribution': cvss_distribution,
                    'location_distribution': location_distribution
                }
            }
            return jsonify(convert_to_json_serializable(result))
        else:
            # Asset-level analysis (unchanged)
            data = loader.load_data(data_file)

            # Ensure we have an Asset object
            if not isinstance(data, Asset):
                return jsonify({'error': f'File {data_file} is not a valid asset-level configuration'}), 400

            asset = data  # Now we know it's an Asset

            # Prepare graph data
            adjacency_matrix = asset.adjacency_matrix
            data_obj = graph_processor.prepare_graph_data(asset, adjacency_matrix)

            # Calculate asset risk
            component_cvs, component_centrality, component_risks, asset_risk = (
                risk_calc.calculate_asset_risk(asset, data_obj)
            )

            # Format component risks for frontend
            formatted_component_risks = []
            for i, risk in enumerate(component_risks):
                component = asset.components[i] if i < len(asset.components) else None
                formatted_component_risks.append({
                    'id': component.id if component else i,
                    'name': component.name if component and hasattr(component,
                                                                    'name') and component.name else f'Component {component.id if component else i}',
                    'risk': risk
                })

            # Rank patches
            patches = prioritizer.rank_patches(asset, AnalysisLevel.ASSET, asset_risk,
                                               adjacency_matrix=adjacency_matrix)

            # Convert patches to frontend-compatible format
            formatted_patches = []
            for patch in patches[:10]:  # Return top 10 patches
                # Handle dictionary format from new patch prioritizer
                if isinstance(patch, dict):
                    formatted_patch = {
                        'id': patch.get('cve_id', ''),
                        'cve_id': patch.get('cve_id', ''),
                        'risk_reduction': patch.get('priority_score', 0),
                        'patched_risk': patch.get('patched_risk', 0),
                        'cvss': patch.get('cvss', 0),
                        'exploit': bool(patch.get('has_exploit', patch.get('exploit', False))),
                        'component_id': patch.get('component_id', ''),
                        'likelihood': 0,  # Not provided in new format
                        'impact': 0,  # Not provided in new format
                        'scopeChanged': False,  # Not provided in new format
                        'ransomWare': False,  # Not provided in new format
                        'epss': patch.get('epss', 0)
                    }
                else:
                    # Fallback for tuple format
                    formatted_patch = {
                        'id': patch[0],  # CVE ID
                        'cve_id': patch[0],
                        'risk_reduction': patch[1],
                        'patched_risk': patch[2],
                        'cvss': patch[3],
                        'exploit': patch[4],
                        'component_id': patch[5],
                        'likelihood': patch[6] if len(patch) > 6 else 0,
                        'impact': patch[7] if len(patch) > 7 else 0,
                        'scopeChanged': patch[8] if len(patch) > 8 else False,
                        'ransomWare': patch[9] if len(patch) > 9 else False,
                        'epss': patch[10] if len(patch) > 10 else 0
                    }
                formatted_patches.append(formatted_patch)

            # Calculate vulnerability statistics for asset-level analysis
            all_vulnerabilities = []
            for component in asset.components:
                for vulnerability in component.vulnerabilities:
                    all_vulnerabilities.append(vulnerability)

            # Calculate statistics
            total_vulnerabilities = len(all_vulnerabilities)
            exploitable_vulnerabilities = sum(1 for v in all_vulnerabilities if v.exploit)
            critical_high_vulnerabilities = sum(1 for v in all_vulnerabilities if v.cvss >= 7.0)

            # CVSS distribution
            cvss_distribution = [0, 0, 0]  # Low, Medium, High
            for v in all_vulnerabilities:
                if v.cvss >= 7.0:
                    cvss_distribution[2] += 1  # High
                elif v.cvss >= 4.0:
                    cvss_distribution[1] += 1  # Medium
                else:
                    cvss_distribution[0] += 1  # Low

            # Location distribution (by component)
            location_distribution = []
            for component in asset.components:
                component_vuln_count = len(component.vulnerabilities)
                if component_vuln_count > 0:
                    location_distribution.append(component_vuln_count)

            # Pad to at least 3 elements
            while len(location_distribution) < 3:
                location_distribution.append(0)

            result = {
                'asset_risk': asset_risk,
                'total_risk': asset_risk,  # Add for frontend compatibility
                'risk': asset_risk,  # CRITICAL FIX: Add 'risk' field for consistency with patch endpoints
                'component_risks': formatted_component_risks,
                'patches': formatted_patches,
                'level': 'asset',
                'config_file': data_file,
                'vulnerability_stats': {
                    'total_vulnerabilities': total_vulnerabilities,
                    'exploitable_vulnerabilities': exploitable_vulnerabilities,
                    'critical_high_vulnerabilities': critical_high_vulnerabilities,
                    'cvss_distribution': cvss_distribution,
                    'location_distribution': location_distribution
                }
            }
            return jsonify(convert_to_json_serializable(result))
    except Exception as e:
        import traceback
        traceback.print_exc()
        error_msg = str(e)
        if "JSON serializable" in error_msg:
            error_msg = f"Data serialization error: {error_msg}. Please check the data format."
        return jsonify({'error': error_msg}), 500


@app.route('/api/create_patch_session', methods=['POST'])
def create_patch_session():
    """Create a new patch session for virtual patching"""
    try:
        data = request.json
        level = data.get('level', 'asset')
        config_file = data.get('file')

        if not config_file:
            return jsonify({'error': 'No config file provided'}), 400

        print(f"\n=== CREATING PATCH SESSION ===")
        print(f"Level: {level}, Config: {config_file}")

        # Generate a unique session ID
        session_id = str(uuid.uuid4())

        # Load the original data and store original vulnerability values
        data_path = os.path.join(parent_dir, 'data', 'asset_withVul_data')
        loader = DataLoader(data_path)
        original_data = loader.load_data(config_file)

        # Store original vulnerability values for restoration AND calculate baseline risk
        original_vulnerabilities = {}
        original_system_risk = None
        vulnerability_mapping = {}  # Track all possible key formats

        if level == 'system' and isinstance(original_data, System):
            print(f"Processing system with {len(original_data.assets)} assets")

            # Calculate original system risk for comparison
            original_system_risk = calculate_system_risk_comprehensive(original_data, config_file)
            print(f"Original system risk calculated: {original_system_risk}")

            # Store original vulnerability values with MULTIPLE key formats for robustness
            for asset in original_data.assets:
                print(f"  Processing asset: {asset.name} (ID: {asset.asset_id})")
                for component in asset.components:
                    print(f"    Processing component: {component.name} (ID: {component.id})")
                    for vuln in component.vulnerabilities:
                        # Store multiple key formats to handle frontend variations
                        key_formats = [
                            f"{vuln.cve_id}_{str(component.id)}_{asset.name}",
                            f"{vuln.cve_id}_{component.id}_{asset.name}",
                            f"{vuln.cve_id}_{str(component.id)}_{str(asset.asset_id)}",
                            f"{vuln.cve_id}_{component.id}_{str(asset.asset_id)}",
                        ]

                        vuln_data = {
                            'impact': float(vuln.impact),
                            'likelihood': float(vuln.likelihood),
                            'cvss': float(vuln.cvss),
                            'exploit': bool(vuln.exploit),
                            'epss': float(vuln.epss),
                            'ransomware': bool(vuln.ransomware)
                        }

                        for key_format in key_formats:
                            original_vulnerabilities[key_format] = vuln_data.copy()
                            vulnerability_mapping[key_format] = {
                                'asset_name': asset.name,
                                'asset_id': asset.asset_id,
                                'component_id': component.id,
                                'cve_id': vuln.cve_id
                            }

                        print(f"      Stored vulnerability: {vuln.cve_id} with keys: {key_formats[0]}")

        elif isinstance(original_data, Asset):
            # Calculate original asset risk
            risk_calc = RiskCalculator()
            graph_processor = GraphProcessor()

            adjacency_matrix = original_data.adjacency_matrix
            data_obj = graph_processor.prepare_graph_data(original_data, adjacency_matrix)
            _, _, _, original_system_risk = risk_calc.calculate_asset_risk(original_data, data_obj)

            for component in original_data.components:
                for vuln in component.vulnerabilities:
                    key_formats = [
                        f"{vuln.cve_id}_{str(component.id)}",
                        f"{vuln.cve_id}_{component.id}",
                    ]

                    vuln_data = {
                        'impact': float(vuln.impact),
                        'likelihood': float(vuln.likelihood),
                        'cvss': float(vuln.cvss),
                        'exploit': bool(vuln.exploit),
                        'epss': float(vuln.epss),
                        'ransomware': bool(vuln.ransomware)
                    }

                    for key_format in key_formats:
                        original_vulnerabilities[key_format] = vuln_data.copy()
                        vulnerability_mapping[key_format] = {
                            'component_id': component.id,
                            'cve_id': vuln.cve_id
                        }

                    print(f"Stored vulnerability: {vuln.cve_id} with key: {key_formats[0]}")

        # Store session data with original vulnerability values AND original risk
        patch_sessions[session_id] = {
            'level': level,
            'config_file': config_file,
            'patched_vulnerabilities': [],
            'original_vulnerabilities': original_vulnerabilities,
            'vulnerability_mapping': vulnerability_mapping,
            'original_system_risk': float(original_system_risk) if original_system_risk else 0.0,
            'created_at': str(uuid.uuid4())
        }

        print(f"SESSION CREATED: {session_id}")
        print(f"  - {len(original_vulnerabilities)} vulnerability keys stored")
        print(f"  - Original risk: {original_system_risk}")
        print(f"  - Sample keys: {list(original_vulnerabilities.keys())[:3]}")

        return jsonify({
            'success': True,
            'session_id': session_id
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/simulate_patch_session', methods=['POST'])
def simulate_patch_session():
    """Simulate patching a vulnerability in a session"""
    try:
        data = request.json
        session_id = data.get('session_id')
        vulnerability_id = data.get('vulnerability_id')
        component_id = data.get('component_id')
        asset_name = data.get('asset_name')

        print(f"\n=== SIMULATING PATCH ===")
        print(f"Session: {session_id}")
        print(f"Vulnerability: {vulnerability_id}")
        print(f"Component: {component_id}")
        print(f"Asset: {asset_name}")

        if not session_id or session_id not in patch_sessions:
            return jsonify({'error': 'Invalid session ID'}), 400

        session = patch_sessions[session_id]
        level = session['level']
        config_file = session['config_file']

        # CRITICAL FIX: Try multiple key formats to find the correct one
        possible_keys = []
        if level == 'system':
            possible_keys = [
                f"{vulnerability_id}_{str(component_id)}_{asset_name}",
                f"{vulnerability_id}_{component_id}_{asset_name}",
                f"{vulnerability_id}_{str(component_id)}_{str(asset_name)}",
                f"{vulnerability_id}_{component_id}_{str(asset_name)}",
            ]
        else:
            possible_keys = [
                f"{vulnerability_id}_{str(component_id)}",
                f"{vulnerability_id}_{component_id}",
            ]

        # Find the correct key from available keys
        patch_key = None
        for key in possible_keys:
            if key in session['original_vulnerabilities']:
                patch_key = key
                break

        if not patch_key:
            print(f"ERROR: No matching key found!")
            print(f"Tried keys: {possible_keys}")
            print(f"Available keys: {list(session['original_vulnerabilities'].keys())[:5]}...")
            # Use the first possible key as fallback
            patch_key = possible_keys[0]

        print(f"Using patch key: {patch_key}")
        print(f"Current patched vulnerabilities: {session['patched_vulnerabilities']}")

        # Toggle patch status
        if patch_key in session['patched_vulnerabilities']:
            session['patched_vulnerabilities'].remove(patch_key)
            is_currently_patched = False
            print(f"UNPATCHING: {patch_key}")
        else:
            session['patched_vulnerabilities'].append(patch_key)
            is_currently_patched = True
            print(f"PATCHING: {patch_key}")

        # Re-run analysis with patched vulnerabilities
        data_path = os.path.join(parent_dir, 'data', 'asset_withVul_data')
        loader = DataLoader(data_path)

        if level == 'system':
            # System-level analysis
            system = loader.load_data(config_file)

            if not isinstance(system, System):
                return jsonify({'error': f'File {config_file} is not a valid system-level configuration'}), 400

            original_vulnerabilities = session.get('original_vulnerabilities', {})

            # STEP 1: Restore ALL vulnerabilities to original values
            restored_count = 0
            vulnerability_count = 0
            for asset in system.assets:
                for component in asset.components:
                    for vuln in component.vulnerabilities:
                        vulnerability_count += 1

                        # Try multiple key formats to find original data
                        vuln_key_candidates = [
                            f"{vuln.cve_id}_{str(component.id)}_{asset.name}",
                            f"{vuln.cve_id}_{component.id}_{asset.name}",
                            f"{vuln.cve_id}_{str(component.id)}_{str(asset.asset_id)}",
                            f"{vuln.cve_id}_{component.id}_{str(asset.asset_id)}",
                        ]

                        restored = False
                        for vuln_key in vuln_key_candidates:
                            if vuln_key in original_vulnerabilities:
                                original_vuln = original_vulnerabilities[vuln_key]
                                vuln.impact = float(original_vuln['impact'])
                                vuln.likelihood = float(original_vuln['likelihood'])
                                vuln.cvss = float(original_vuln['cvss'])
                                vuln.exploit = bool(original_vuln['exploit'])
                                vuln.epss = float(original_vuln['epss'])
                                vuln.ransomware = bool(original_vuln['ransomware'])
                                restored_count += 1
                                restored = True
                                break

                        if not restored:
                            print(f"WARNING: Could not restore {vuln.cve_id} in {asset.name}/{component.id}")

            print(f"RESTORED: {restored_count}/{vulnerability_count} vulnerabilities to original values")

            # STEP 2: Apply patches to specifically patched vulnerabilities
            patched_count = 0
            for asset in system.assets:
                for component in asset.components:
                    for vuln in component.vulnerabilities:
                        # Check all possible key formats
                        vuln_key_candidates = [
                            f"{vuln.cve_id}_{str(component.id)}_{asset.name}",
                            f"{vuln.cve_id}_{component.id}_{asset.name}",
                            f"{vuln.cve_id}_{str(component.id)}_{str(asset.asset_id)}",
                            f"{vuln.cve_id}_{component.id}_{str(asset.asset_id)}",
                        ]

                        for vuln_key in vuln_key_candidates:
                            if vuln_key in session['patched_vulnerabilities']:
                                print(f"APPLYING PATCH TO {vuln_key}: CVSS {vuln.cvss} -> 0.01")

                                # Apply patch - set to very low values
                                vuln.impact = 0.01
                                vuln.likelihood = 0.01
                                vuln.cvss = 0.01
                                vuln.exploit = False
                                vuln.epss = 0.01
                                patched_count += 1
                                break  # Only patch once per vulnerability

            print(f"PATCHED: {patched_count} vulnerabilities")

            # STEP 3: Calculate new system risk using comprehensive method
            print("Calculating new system risk...")
            new_system_risk = calculate_system_risk_comprehensive(system, config_file)

            # Calculate risk reduction
            original_risk = session.get('original_system_risk', new_system_risk)
            if original_risk and original_risk > 0:
                risk_reduction_amount = original_risk - new_system_risk
                risk_reduction_percentage = (risk_reduction_amount / original_risk) * 100
            else:
                risk_reduction_amount = 0
                risk_reduction_percentage = 0

            print(f"RISK CALCULATION:")
            print(f"  Original: {original_risk}")
            print(f"  Current: {new_system_risk}")
            print(f"  Reduction: {risk_reduction_amount} ({risk_reduction_percentage:.2f}%)")

            # Format asset risks for frontend
            formatted_asset_risks = []
            for asset in system.assets:
                formatted_asset_risks.append({
                    'id': asset.asset_id,
                    'name': asset.name,
                    'criticality': getattr(asset, 'final_criticality', asset.criticality_level),
                    'risk': getattr(asset, 'total_propagated_risk', 0.0),
                    'originalRisk': getattr(asset, 'total_propagated_risk', 0.0)
                })

            result = {
                'success': True,
                'patched_risk': new_system_risk,
                'risk': new_system_risk,
                'original_risk': original_risk,
                'risk_reduction_amount': risk_reduction_amount,
                'risk_reduction_percentage': risk_reduction_percentage,
                'asset_risks': formatted_asset_risks,
                'is_patching': is_currently_patched,
                'debug_info': {
                    'patch_key': patch_key,
                    'patched_count': patched_count,
                    'restored_count': restored_count,
                    'total_patched_vulnerabilities': len(session['patched_vulnerabilities']),
                    'original_system_risk': original_risk,
                    'current_system_risk': new_system_risk,
                    'total_vulnerabilities': vulnerability_count
                }
            }
            return jsonify(convert_to_json_serializable(result))
        else:
            # Asset-level analysis (similar improvements)
            asset = loader.load_data(config_file)

            if not isinstance(asset, Asset):
                return jsonify({'error': f'File {config_file} is not a valid asset-level configuration'}), 400

            original_vulnerabilities = session.get('original_vulnerabilities', {})

            # STEP 1: Restore all vulnerabilities to original values
            restored_count = 0
            for component in asset.components:
                for vuln in component.vulnerabilities:
                    vuln_key_candidates = [
                        f"{vuln.cve_id}_{str(component.id)}",
                        f"{vuln.cve_id}_{component.id}",
                    ]

                    for vuln_key in vuln_key_candidates:
                        if vuln_key in original_vulnerabilities:
                            original_vuln = original_vulnerabilities[vuln_key]
                            vuln.impact = float(original_vuln['impact'])
                            vuln.likelihood = float(original_vuln['likelihood'])
                            vuln.cvss = float(original_vuln['cvss'])
                            vuln.exploit = bool(original_vuln['exploit'])
                            vuln.epss = float(original_vuln['epss'])
                            vuln.ransomware = bool(original_vuln['ransomware'])
                            restored_count += 1
                            break

            print(f"ASSET-LEVEL: Restored {restored_count} vulnerabilities to original values")

            # STEP 2: Apply patches
            patched_count = 0
            for component in asset.components:
                for vuln in component.vulnerabilities:
                    vuln_key_candidates = [
                        f"{vuln.cve_id}_{str(component.id)}",
                        f"{vuln.cve_id}_{component.id}",
                    ]

                    for vuln_key in vuln_key_candidates:
                        if vuln_key in session['patched_vulnerabilities']:
                            print(f"APPLYING PATCH TO {vuln_key}: CVSS {vuln.cvss} -> 0.01")

                            vuln.impact = 0.01
                            vuln.likelihood = 0.01
                            vuln.cvss = 0.01
                            vuln.exploit = False
                            vuln.epss = 0.01
                            patched_count += 1
                            break

            print(f"ASSET-LEVEL: Applied {patched_count} patches")

            # Calculate new asset risk
            risk_calc = RiskCalculator()
            graph_processor = GraphProcessor()
            adjacency_matrix = asset.adjacency_matrix
            data_obj = graph_processor.prepare_graph_data(asset, adjacency_matrix)
            _, _, _, new_asset_risk = risk_calc.calculate_asset_risk(asset, data_obj)

            # Calculate risk reduction
            original_risk = session.get('original_system_risk', new_asset_risk)
            if original_risk and original_risk > 0:
                risk_reduction_amount = original_risk - new_asset_risk
                risk_reduction_percentage = (risk_reduction_amount / original_risk) * 100
            else:
                risk_reduction_amount = 0
                risk_reduction_percentage = 0

            print(f"ASSET RISK CALCULATION:")
            print(f"  Original: {original_risk}")
            print(f"  Current: {new_asset_risk}")
            print(f"  Reduction: {risk_reduction_amount} ({risk_reduction_percentage:.2f}%)")

            result = {
                'success': True,
                'patched_risk': new_asset_risk,
                'risk': new_asset_risk,
                'original_risk': original_risk,
                'risk_reduction_amount': risk_reduction_amount,
                'risk_reduction_percentage': risk_reduction_percentage,
                'is_patching': is_currently_patched,
                'debug_info': {
                    'patch_key': patch_key,
                    'patched_count': patched_count,
                    'restored_count': restored_count,
                    'total_patched_vulnerabilities': len(session['patched_vulnerabilities']),
                    'original_asset_risk': original_risk,
                    'current_asset_risk': new_asset_risk
                }
            }
            return jsonify(convert_to_json_serializable(result))

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/reset_patch_session', methods=['POST'])
def reset_patch_session():
    """Reset all patches in a session"""
    try:
        data = request.json
        session_id = data.get('session_id')

        if not session_id or session_id not in patch_sessions:
            return jsonify({'error': 'Invalid session ID'}), 400

        session = patch_sessions[session_id]

        print(f"\n=== RESETTING PATCH SESSION ===")
        print(f"Session: {session_id}")
        print(f"Clearing {len(session['patched_vulnerabilities'])} patched vulnerabilities")

        # Clear all patched vulnerabilities
        session['patched_vulnerabilities'] = []

        # Return the original system risk
        original_risk = session.get('original_system_risk', 0.0)

        result = {
            'success': True,
            'patched_risk': original_risk,
            'risk': original_risk,
            'original_risk': original_risk,
            'risk_reduction_amount': 0,
            'risk_reduction_percentage': 0,
            'is_patching': False,
            'message': 'All patches have been reset'
        }

        return jsonify(convert_to_json_serializable(result))

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5001)