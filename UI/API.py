from flask import Flask, request, jsonify, send_from_directory
import os
import json
import subprocess
import threading
import sys
from flask_cors import CORS
import numpy as np
import time

parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(parent_dir)
src_dir = os.path.join(parent_dir, 'src')
sys.path.append(src_dir)
os.chdir(src_dir)
import conf
from data_processing import (
    prepare_graph_data,
    load_asset_data,
    load_system_data,
    generate_sub_graph,
    generate_network_graph
)
from risk_calculation import (
    calculate_risk,
    recalculate_asset_criticality
)
from patch_prioritization import (
    rank_patches,
    verify_risk_reduction,
    rank_vulnerabilities_by_cvss,
    simulate_patch_asset,
    simulate_patch_system
)
from cal_dependence import generate_dependence
from virtual_patching import (
    create_patch_session,
    simulate_patch_with_session,
    find_vulnerability_indices,
    find_vulnerability_indices_system
)

# Change back to the original directory
os.chdir(parent_dir)

app = Flask(__name__, static_folder='frontend/build', static_url_path='')
CORS(app, resources={r"/*": {"origins": "*"}})

# Store analysis results
analysis_results = {}
analysis_status = {}


@app.route('/api/create_patch_session', methods=['POST'])
def create_patch_session_api():
    """Create a new patching session"""
    req_data = request.json
    level = req_data.get('level', 'asset')
    config_file = req_data.get('file')

    if not config_file:
        return jsonify({'error': 'No configuration file provided'}), 400

    try:
        session_id = create_patch_session(level, config_file)
        return jsonify({'success': True, 'session_id': session_id})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/simulate_patch_session', methods=['POST'])
def simulate_patch_session_api():
    """Simulate patching a vulnerability within a session"""
    req_data = request.json
    session_id = req_data.get('session_id')
    vulnerability_id = req_data.get('vulnerability_id')

    if not session_id or not vulnerability_id:
        return jsonify({'error': 'Missing required parameters'}), 400

    try:
        result = simulate_patch_with_session(session_id, vulnerability_id)
        return jsonify({'success': True, 'results': result})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/simulate_patch', methods=['POST'])
def simulate_patch_api():
    """Simulate patching a vulnerability"""
    req_data = request.json
    session_id = req_data.get('session_id')
    vulnerability_id = req_data.get('vulnerability_id')

    if not session_id or not vulnerability_id:
        return jsonify({'error': 'Missing required parameters'}), 400

    try:
        result = simulate_patch_with_session(session_id, vulnerability_id)
        return jsonify({'success': True, 'results': result})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')


@app.route('/api/configs', methods=['GET'])
def get_configs():
    """Return available configuration files"""
    configs = {
        'asset': [],
        'system': []
    }

    # Scan the data directory for configuration files
    if os.path.exists(conf.asset_vul_data_path):
        for filename in os.listdir(conf.asset_vul_data_path):
            if filename.endswith('.json'):
                # Check if it's an asset or system file based on content or naming convention
                if 'openPLC' in filename:
                    configs['asset'].append(filename)
                elif 'ICS' in filename:
                    configs['system'].append(filename)
                else:
                    # For other files, try to determine the type
                    try:
                        file_path = os.path.join(conf.asset_vul_data_path, filename)
                        with open(file_path, 'r') as f:
                            data = json.load(f)
                        if 'Assets' in data:
                            configs['system'].append(filename)
                        else:
                            configs['asset'].append(filename)
                    except:
                        # If we can't determine the type, default to asset
                        configs['asset'].append(filename)

    return jsonify(configs)


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Run analysis based on provided parameters"""
    try:
        print("Received analysis request:", request.json)
        data = request.json
        level = data.get('level', 'asset')
        config_file = data.get('file')

        if not config_file:
            return jsonify({'error': 'No configuration file provided'}), 400

        job_id = f"{level}_{config_file}"
        print(f"Starting analysis job: {job_id}")

        # Update status to 'running'
        analysis_status[job_id] = 'running'

        # Start analysis in a background thread
        thread = threading.Thread(target=run_analysis, args=(level, config_file, job_id))
        thread.start()
        print(f"Analysis thread started for job: {job_id}")

        return jsonify({'status': 'running', 'job_id': job_id})
    except Exception as e:
        import traceback
        print("Error in /api/analyze endpoint:")
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/status/<job_id>', methods=['GET'])
def get_status(job_id):
    """Get the status of a running analysis job"""
    status = analysis_status.get(job_id, 'unknown')
    return jsonify({'status': status})


@app.route('/api/results/<job_id>', methods=['GET'])
def get_results(job_id):
    """Get analysis results by job ID"""
    if job_id in analysis_results:
        return jsonify({
            'status': analysis_status.get(job_id, 'completed'),
            'results': analysis_results[job_id]
        })
    else:
        return jsonify({'status': analysis_status.get(job_id, 'unknown')})


@app.route('/api/simulate_patch', methods=['POST'])
def simulate_patch():
    """Simulate patching a vulnerability and return recalculated risks"""
    req_data = request.json
    level = req_data.get('level', 'asset')
    config_file = req_data.get('file')
    vulnerability_id = req_data.get('vulnerability_id')

    if not config_file or not vulnerability_id:
        return jsonify({'error': 'Missing required parameters'}), 400

    try:
        start_time = time.time()

        # Asset level Analysis
        if level == "asset":
            # Load and prepare data
            data = load_asset_data(os.path.join(conf.asset_vul_data_path, config_file))
            adjacency_matrix = np.array(data.adjacency_matrix)
            data_obj = prepare_graph_data(data, adjacency_matrix)

            # Calculate initial risks
            initial_cvs, initial_centrality, initial_component_risks, initial_asset_risk = calculate_risk(
                data, data_obj=data_obj, level='asset'
            )

            # Find component and vulnerability indices
            comp_idx, vul_idx = find_vulnerability_indices(data, vulnerability_id)

            # Simulate patching
            patched_data = simulate_patch_asset(data, comp_idx, vul_idx)
            patched_data_obj = prepare_graph_data(patched_data, adjacency_matrix)

            # Calculate patched risks
            _, _, patched_component_risks, patched_asset_risk = calculate_risk(
                patched_data, data_obj=patched_data_obj, level='asset'
            )

            # Calculate risk reduction
            risk_reduction = initial_asset_risk - patched_asset_risk

            # Format results
            result = {
                'original_risk': float(initial_asset_risk),
                'patched_risk': float(patched_asset_risk),
                'risk_reduction': float(risk_reduction),
                'original_component_risks': [float(risk) for risk in initial_component_risks],
                'patched_component_risks': [float(risk) for risk in patched_component_risks],
                'vulnerability': {
                    'id': vulnerability_id,
                    'component_id': comp_idx + 1,
                    'cvss': data.components[comp_idx].vulnerabilities[vul_idx].cvss,
                    'exploit': bool(data.components[comp_idx].vulnerabilities[vul_idx].exploit)
                }
            }

        # System level analysis
        elif level == "system":
            data = load_system_data(os.path.join(conf.asset_vul_data_path, config_file))
            scenario_id = config_file.split('_')[1].split('.')[0]

            # Generate asset and component centrality values
            centrality_dict = generate_dependence(data, scenario_id)
            sys_comp_centrality = centrality_dict['component_centrality']
            asset_centrality_provided = centrality_dict['asset_centrality']

            # Generate sub-graphs, calculate risks
            asset_sub_graphs = {}
            asset_centrality = {}

            # Assign provided centrality values
            for asset in data.assets:
                asset_id = asset.asset_id
                asset_centrality[asset_id] = asset_centrality_provided.get(asset_id, 0)

            for asset in data.assets:
                # Generate subgraph and calculate risk
                G, data_obj = generate_sub_graph(asset)
                _, _, _, total_propagated_risk = calculate_risk(asset, data_obj=data_obj, level='asset')
                asset.total_propagated_risk = total_propagated_risk

                # Store subgraph and risks
                asset_sub_graphs[asset.name] = {
                    'graph': G,
                    'data_obj': data_obj,
                    'total_propagated_risk': total_propagated_risk
                }

            # Recalculate asset criticality
            updated_criticality, final_criticality = recalculate_asset_criticality(
                data.assets, asset_centrality
            )

            # Update criticality levels
            for asset in data.assets:
                asset_id = asset.asset_id
                asset.updated_criticality = updated_criticality[asset_id]
                asset.final_criticality = final_criticality[asset_id]

            # Generate network graph
            main_graph = generate_network_graph(data)

            # Calculate system-level risk
            initial_system_risk = calculate_risk(
                data, level='system', G=main_graph, comp_centrality_data=sys_comp_centrality
            )

            # Find vulnerability indices
            asset_idx, comp_idx, vul_idx = find_vulnerability_indices_system(data, vulnerability_id)

            # Simulate patching
            patched_data = simulate_patch_system(data, asset_idx, comp_idx, vul_idx)

            # Recalculate risks for patched data
            for asset in patched_data.assets:
                G, data_obj = generate_sub_graph(asset)
                _, _, _, total_propagated_risk = calculate_risk(
                    asset, data_obj=data_obj, level='asset'
                )
                asset.total_propagated_risk = total_propagated_risk

            # Calculate new system risk
            patched_system_risk = calculate_risk(
                patched_data, level='system', G=main_graph, comp_centrality_data=sys_comp_centrality
            )

            # Calculate risk reduction
            risk_reduction = initial_system_risk - patched_system_risk

            # Get asset name and component id
            asset_name = data.assets[asset_idx].name
            component_id = data.assets[asset_idx].components[comp_idx].id

            # Format results
            result = {
                'original_risk': float(initial_system_risk),
                'patched_risk': float(patched_system_risk),
                'risk_reduction': float(risk_reduction),
                'vulnerability': {
                    'id': vulnerability_id,
                    'asset_name': asset_name,
                    'component_id': component_id,
                    'cvss': data.assets[asset_idx].components[comp_idx].vulnerabilities[vul_idx].cvss,
                    'exploit': bool(data.assets[asset_idx].components[comp_idx].vulnerabilities[vul_idx].exploit)
                },
                'asset_risks': []
            }

            # Add asset risks to result
            original_assets = {asset.name: asset for asset in data.assets}
            patched_assets = {asset.name: asset for asset in patched_data.assets}

            for name, asset in original_assets.items():
                patched_asset = patched_assets.get(name)
                if patched_asset:
                    result['asset_risks'].append({
                        'name': name,
                        'original_risk': float(asset.total_propagated_risk),
                        'patched_risk': float(patched_asset.total_propagated_risk),
                        'risk_reduction': float(asset.total_propagated_risk - patched_asset.total_propagated_risk),
                        'criticality': int(asset.final_criticality)
                    })

        end_time = time.time()
        print(f"Virtual patching simulation took {end_time - start_time:.2f} seconds")

        return jsonify({
            'success': True,
            'level': level,
            'vulnerability_id': vulnerability_id,
            'results': result
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file uploads"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if file and file.filename.endswith('.json'):
        # Save the file to the data directory
        os.makedirs(conf.asset_vul_data_path, exist_ok=True)
        file_path = os.path.join(conf.asset_vul_data_path, file.filename)
        file.save(file_path)

        # Try to determine if it's an asset or system file
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            # Check for system-level identifiers
            if 'Assets' in data:
                file_type = 'system'
            else:
                file_type = 'asset'
        except:
            # Default to asset type if we can't determine
            file_type = 'asset'

        return jsonify({
            'success': True,
            'filename': file.filename,
            'file_type': file_type
        })

    return jsonify({'error': 'Invalid file type. Only JSON files are allowed.'}), 400


def run_analysis(level, config_file, job_id):
    """Run the analysis and store results"""
    try:
        start_time = time.time()

        # Asset level Analysis
        if level == "asset":
            # Load and prepare data
            data = load_asset_data(os.path.join(conf.asset_vul_data_path, config_file))
            adjacency_matrix = np.array(data.adjacency_matrix)
            data_obj = prepare_graph_data(data, adjacency_matrix)

            # Calculate initial risks
            initial_cvs, initial_centrality, initial_component_risks, initial_asset_risk = calculate_risk(
                data, data_obj=data_obj, level='asset'
            )
            print(f'Initial Asset Risk: {initial_asset_risk:.4f}')

            # Rank patches
            patch_rankings = rank_patches(
                data,
                adjacency_matrix=adjacency_matrix,
                initial_risk=initial_asset_risk,
                level='asset'
            )

            # Format results
            component_risks = []
            for idx, risk in enumerate(initial_component_risks):
                if idx < len(data.components):
                    component = data.components[idx]
                    component_risks.append({
                        'id': component.id,
                        'name': f"{component.name} {component.version}",
                        'risk': float(risk),
                        'centrality': float(initial_centrality[idx])
                    })

            formatted_patch_rankings = []
            for patch in patch_rankings:
                # Unpack the patch tuple into named variables
                cve_id, risk_reduction, patched_risk, cvss, exploit, component_id, likelihood, impact, scope_changed, ransomware, epss = patch

                formatted_patch_rankings.append({
                    'id': cve_id,
                    'risk_reduction': float(risk_reduction),
                    'patched_risk': float(patched_risk),
                    'cvss': float(cvss),
                    'exploit': bool(exploit),
                    'component_id': str(component_id),
                    'likelihood': float(likelihood),
                    'impact': float(impact),
                    'scopeChanged': bool(scope_changed),
                    'ransomWare': bool(ransomware),
                    'epss': float(epss)
                })

            results = {
                'level': 'asset',
                'config_file': config_file,
                'total_risk': float(initial_asset_risk),
                'component_risks': component_risks,
                'patch_rankings': formatted_patch_rankings
            }

            # System level analysis
        elif level == "system":
            data = load_system_data(os.path.join(conf.asset_vul_data_path, config_file))
            scenario_id = config_file.split('_')[1].split('.')[0]

            # Generate asset and component centrality values
            centrality_dict = generate_dependence(data, scenario_id)
            sys_comp_centrality = centrality_dict['component_centrality']
            asset_centrality_provided = centrality_dict['asset_centrality']

            # Generate sub-graphs, calculate risks
            asset_sub_graphs = {}
            asset_centrality = {}
            asset_risks = []

            # Assign provided centrality values
            for asset in data.assets:
                asset_id = asset.asset_id
                asset_centrality[asset_id] = asset_centrality_provided.get(asset_id, 0)

            for asset in data.assets:
                # Generate subgraph and calculate risk
                G, data_obj = generate_sub_graph(asset)
                _, asset_comp_centrality, _, total_propagated_risk = calculate_risk(
                    asset, data_obj=data_obj, level='asset'
                )
                asset.total_propagated_risk = total_propagated_risk

                # Store subgraph and risks
                asset_sub_graphs[asset.name] = {
                    'graph': G,
                    'data_obj': data_obj,
                    'total_propagated_risk': total_propagated_risk
                }

            # Recalculate asset criticality
            updated_criticality, final_criticality = recalculate_asset_criticality(
                data.assets, asset_centrality
            )

            # Update criticality levels and collect asset risks
            for asset in data.assets:
                asset_id = asset.asset_id
                asset.updated_criticality = updated_criticality[asset_id]
                asset.final_criticality = final_criticality[asset_id]

                # Add to asset risks list
                asset_risks.append({
                    'id': asset.asset_id,
                    'name': asset.name,
                    'criticality': int(asset.final_criticality),
                    'centrality': float(asset_centrality[asset.asset_id]),
                    'risk': float(asset.total_propagated_risk)
                })

            # Generate network graph
            main_graph = generate_network_graph(data)

            # Calculate system-level risk
            initial_system_risk = calculate_risk(
                data, level='system', G=main_graph, comp_centrality_data=sys_comp_centrality
            )
            print(f"Initial System-level Risk Score: {initial_system_risk}")

            # Rank patches
            patch_rankings = rank_patches(
                data, level='system',
                initial_risk=initial_system_risk,
                main_graph=main_graph,
                comp_centrality_data=sys_comp_centrality
            )

            # Format patch rankings
            formatted_patch_rankings = []
            for patch in patch_rankings:
                # Unpack the patch tuple into named variables
                cve_id, risk_reduction, patched_risk, cvss, exploit, component_id, asset_name, likelihood, impact, scope_changed, ransomware, epss = patch

                formatted_patch_rankings.append({
                    'id': cve_id,
                    'risk_reduction': float(risk_reduction),
                    'patched_risk': float(patched_risk),
                    'cvss': float(cvss),
                    'exploit': bool(exploit),
                    'component_id': str(component_id),
                    'asset_name': str(asset_name),
                    'likelihood': float(likelihood),
                    'impact': float(impact),
                    'scopeChanged': bool(scope_changed),
                    'ransomWare': bool(ransomware),
                    'epss': float(epss)
                })

            # Format results
            results = {
                'level': 'system',
                'config_file': config_file,
                'total_risk': float(initial_system_risk),
                'asset_risks': asset_risks,
                'patch_rankings': formatted_patch_rankings
            }

        else:
            raise ValueError(f"Invalid analysis level: {level}")

        end_time = time.time()
        print(f"Analysis completed in {end_time - start_time:.2f} seconds")

        # Store results
        analysis_results[job_id] = results
        analysis_status[job_id] = 'completed'

    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error during analysis: {str(e)}")
        analysis_status[job_id] = 'error'
        analysis_results[job_id] = {'error': str(e)}


if __name__ == '__main__':
    print(f"Flask app directory: {os.getcwd()}")
    print(f"Static folder path: {os.path.abspath(app.static_folder)}")
    print("Starting Flask server on http://localhost:5000/")

    # Disable auto-reloading to prevent the restart issue
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)