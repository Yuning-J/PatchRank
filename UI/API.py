from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import sys
import json
import numpy as np
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
            
            # Extract scenario ID from filename
            scenario_id = data_file.split('_')[1].split('.')[0] if '_' in data_file else 'default'
            
            # Generate dependency analysis
            asset_data_path = os.path.join(parent_dir, 'data', 'asset_data')
            dependency_calc = DependencyCalculator(asset_data_path)
            centrality_dict = dependency_calc.generate_dependence(system, scenario_id)
            sys_comp_centrality = centrality_dict['component_centrality']
            
            # Process each asset
            for asset in system.assets:
                G, data_obj = graph_processor.generate_sub_graph(asset)
                _, _, _, total_propagated_risk = risk_calc.calculate_asset_risk(asset, data_obj)
                asset.total_propagated_risk = total_propagated_risk
            
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
            
            # Calculate system-level risk with appropriate criticality threshold
            # Since final_criticality is now scaled 1-10, use threshold of 6 for "high criticality"
            system_risk = risk_calc.calculate_system_risk(main_graph, system, sys_comp_centrality, criticality_threshold=6)
            
            # If system risk is 0, use a fallback calculation based on asset risks
            if system_risk == 0:
                # Fallback: sum of all asset risks weighted by their criticality
                fallback_risk = 0.0
                for asset in system.assets:
                    if hasattr(asset, 'total_propagated_risk') and hasattr(asset, 'updated_criticality'):
                        asset_contribution = asset.total_propagated_risk * (asset.updated_criticality + 0.1)  # Add 0.1 to avoid 0
                        fallback_risk += asset_contribution
                
                # If fallback is still 0, use CVSS-based calculation
                if fallback_risk == 0:
                    for asset in system.assets:
                        for component in asset.components:
                            for vulnerability in component.vulnerabilities:
                                fallback_risk += vulnerability.cvss * 0.1  # Simple CVSS-based risk
                
                system_risk = fallback_risk
            

            
            # Rank patches
            patches = prioritizer.rank_patches(system, AnalysisLevel.SYSTEM, system_risk, 
                                             main_graph=main_graph, comp_centrality_data=sys_comp_centrality)
            
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
                        'exploit': patch.get('exploit', False),
                        'component_id': patch.get('component_id', ''),
                        'asset_name': patch.get('asset_id', ''),
                        'likelihood': 0,  # Not provided in new format
                        'impact': 0,      # Not provided in new format  
                        'scopeChanged': False,  # Not provided in new format
                        'ransomWare': False,    # Not provided in new format
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
            exploitable_vulnerabilities = sum(1 for v in all_vulnerabilities if v.exploit > 0)
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
                    'criticality': asset.final_criticality,
                    'risk': asset.total_propagated_risk,
                    'originalRisk': asset.total_propagated_risk  # For virtual patching
                })
            
            result = {
                'system_risk': system_risk,
                'total_risk': system_risk,  # Add for frontend compatibility
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
            # Asset-level analysis
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
                    'name': component.name if component and hasattr(component, 'name') and component.name else f'Component {component.id if component else i}',
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
                        'exploit': patch.get('exploit', False),
                        'component_id': patch.get('component_id', ''),
                        'likelihood': 0,  # Not provided in new format
                        'impact': 0,      # Not provided in new format
                        'scopeChanged': False,  # Not provided in new format
                        'ransomWare': False,    # Not provided in new format
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
            
            result = {
                'asset_risk': asset_risk,
                'total_risk': asset_risk,  # Add for frontend compatibility
                'component_risks': formatted_component_risks,
                'patches': formatted_patches,
                'level': 'asset',
                'config_file': data_file
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
        
        # Generate a unique session ID
        session_id = str(uuid.uuid4())
        
        # Store session data
        patch_sessions[session_id] = {
            'level': level,
            'config_file': config_file,
            'patched_vulnerabilities': [],
            'created_at': str(uuid.uuid4())  # Simple timestamp placeholder
        }
        
        return jsonify({
            'success': True,
            'session_id': session_id
        })
    except Exception as e:
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
        
        if not session_id or session_id not in patch_sessions:
            return jsonify({'error': 'Invalid session ID'}), 400
        
        session = patch_sessions[session_id]
        level = session['level']
        config_file = session['config_file']
        
        # Create patch key
        patch_key = f"{vulnerability_id}_{component_id}"
        if asset_name:
            patch_key += f"_{asset_name}"
        
        # Toggle patch status
        if patch_key in session['patched_vulnerabilities']:
            session['patched_vulnerabilities'].remove(patch_key)
            is_patching = False
        else:
            session['patched_vulnerabilities'].append(patch_key)
            is_patching = True
        
        # Re-run analysis with patched vulnerabilities
        # Initialize components
        data_path = os.path.join(parent_dir, 'data', 'asset_withVul_data')
        loader = DataLoader(data_path)
        risk_calc = RiskCalculator()
        prioritizer = PatchPrioritizer()
        graph_processor = GraphProcessor()
        
        if level == 'system':
            # System-level analysis
            system_data_path = os.path.join(parent_dir, 'data', 'asset_withVul_data')
            loader = DataLoader(system_data_path)
            data = loader.load_data(config_file)
            
            if not isinstance(data, System):
                return jsonify({'error': f'File {config_file} is not a valid system-level configuration'}), 400
            
            system = data
            
            # Apply virtual patches
            for asset in system.assets:
                for component in asset.components:
                    for vuln in component.vulnerabilities:
                        vuln_key = f"{vuln.cve_id}_{component.id}_{asset.name}"
                        if vuln_key in session['patched_vulnerabilities']:
                            # Mark vulnerability as patched (set impact to 0)
                            vuln.impact = 0.0
                            vuln.likelihood = 0.0
            
            # Extract scenario ID from filename
            scenario_id = config_file.split('_')[1].split('.')[0] if '_' in config_file else 'default'
            
            # Generate dependency analysis
            asset_data_path = os.path.join(parent_dir, 'data', 'asset_data')
            dependency_calc = DependencyCalculator(asset_data_path)
            centrality_dict = dependency_calc.generate_dependence(system, scenario_id)
            sys_comp_centrality = centrality_dict['component_centrality']
            
            # Process each asset
            for asset in system.assets:
                G, data_obj = graph_processor.generate_sub_graph(asset)
                _, _, _, total_propagated_risk = risk_calc.calculate_asset_risk(asset, data_obj)
                asset.total_propagated_risk = total_propagated_risk
            
            # Generate network graph
            main_graph = graph_processor.generate_network_graph(system)
            
            # Calculate system-level risk
            system_risk = risk_calc.calculate_system_risk(main_graph, system, sys_comp_centrality, criticality_threshold=3)
            
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
            
            # Format asset risks for frontend (matching the analyze endpoint format)
            formatted_asset_risks = []
            for asset in system.assets:
                formatted_asset_risks.append({
                    'id': asset.asset_id,
                    'name': asset.name,
                    'criticality': asset.final_criticality,
                    'risk': asset.total_propagated_risk,
                    'originalRisk': asset.total_propagated_risk
                })
            
            result = {
                'success': True,
                'patched_risk': system_risk,
                'risk': system_risk,
                'asset_risks': formatted_asset_risks,
                'is_patching': is_patching
            }
            return jsonify(convert_to_json_serializable(result))
        else:
            # Asset-level analysis
            data = loader.load_data(config_file)
            
            if not isinstance(data, Asset):
                return jsonify({'error': f'File {config_file} is not a valid asset-level configuration'}), 400
            
            asset = data
            
            # Apply virtual patches
            for component in asset.components:
                for vuln in component.vulnerabilities:
                    vuln_key = f"{vuln.cve_id}_{component.id}"
                    if vuln_key in session['patched_vulnerabilities']:
                        # Mark vulnerability as patched (set impact to 0)
                        vuln.impact = 0.0
                        vuln.likelihood = 0.0
            
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
                    'name': component.name if component and hasattr(component, 'name') and component.name else f'Component {component.id if component else i}',
                    'risk': risk
                })
            
            result = {
                'success': True,
                'patched_risk': asset_risk,
                'risk': asset_risk,
                'patched_component_risks': formatted_component_risks,
                'is_patching': is_patching
            }
            return jsonify(convert_to_json_serializable(result))
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5001)