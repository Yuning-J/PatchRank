import json
import os
import conf
from data_processing import load_system_data, load_asset_data
import requests


# Function to get EPSS score for a given CVE
def get_epss_score(cve_id):
    try:
        response = requests.get(f'https://api.first.org/data/v1/epss?cve={cve_id}')
        response.raise_for_status()
        data = response.json()
        if 'data' in data and data['data']:
            return float(data['data'][0]['epss'])  # Ensure EPSS score is a float
    except requests.RequestException as e:
        print(f"Error fetching EPSS score for {cve_id}: {e}")
    return 0.0  # Return 0.0 as a float if EPSS score is not available or an error occurs


if __name__ == "__main__":
    epss = get_epss_score("CVE-2016-8673")
    print(str(epss))
