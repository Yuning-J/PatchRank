# PatchRanking

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/Yuning-J/PatchRank">
  </a>
  <br />

  <!-- Badges -->
  <img src="https://img.shields.io/github/repo-size/Yuning-J/PatchRank?style=for-the-badge" alt="GitHub repo size" height="25">
  <img src="https://img.shields.io/github/last-commit/Yuning-J/PatchRank?style=for-the-badge" alt="GitHub last commit" height="25">
  <br />
  
  <h3 align="center"> PatchRank: Multi-Level Explainable Vulnerability Patch Ranking</h3>
  <p align="left">
   This project presents a comprehensive framework for risk aggregation and vulnerability prioritization tailored for complex systems, such as industrial control systems (ICS), IoT environments, and enterprise networks. Our method employs a graph-based approach to model system dependencies and attack paths, enabling a multi-level analysis that captures both asset and component-level risks. If you use this tool in your academic work, you can find the citation in the end.
 
  </p>
</p>

## Quick Start

### Setup

```bash
pip install -r requirements.txt
```

### Command-Line Usage

PatchRank supports comprehensive command-line analysis with enhanced methodology:

```bash
# Enhanced asset-level analysis with graph-based risk calculation
python src/main.py --level asset --data paper_openPLC.json

# Enhanced system-level analysis using paper methodology (R_system = R_network + Σ R_host,hm)
python src/main.py --level system --data paper_ICS.json

# CVSS-only vulnerability ranking (no sophisticated risk calculation)
python src/main.py --level asset --data paper_openPLC.json --cvss_only
```

**Input Files:**
- Asset-level files: `data/asset_withVul_data/` (e.g., `paper_openPLC.json`)
- System-level files: `data/asset_withVul_data/` (e.g., `paper_ICS.json`, `paper_ES.json`)
- Results include risk scores, vulnerability statistics, and prioritized patch recommendations

### Web Interface Demo

https://github.com/Yuning-J/PatchRank/blob/main/figs/demo_patchRank.mp4

PatchRank includes a complete web interface for interactive analysis:

```bash
# Start the API server
cd UI && python API.py

# In another terminal, start the React frontend
cd UI/frontend && npm install && npm start
```

Then navigate to `http://localhost:3000` for the full web interface with:
- Interactive vulnerability analysis
- Real-time patch prioritization
- Shows actual risk reduction values, not just CVSS scores
- Full support for complex multi-asset systems

For detailed setup instructions, see `UI/README.md`.

## Cite

If you use this tool in your academic work, you can cite it using

```bibtex
@article{jiang2025vulrg,
  title={VulRG: Multi-Level Explainable Vulnerability Patch Ranking for Complex Systems Using Graphs},
  author={Jiang, Yuning and Oo, Nay and Meng, Qiaoran and Lim, Hoon Wei and Sikdar, Biplab},
  journal={arXiv preprint arXiv:2502.11143},
  year={2025}
}
```

## Application Scenario:

### Scenario 1:
Given an OpenPLC with the following configuration:

<p align="center">
<img src="https://github.com/Yuning-J/VulRG/blob/main/figs/openPLC.png" alt="System" width="250px">
</p>

The expected outcome for asset risk calculation and TOP-3 vulnerability ranking using our VulRG are:
  
```bash
Initial Asset Risk: 2.8561

Top 3 patches:
1. CVE: CVE-2016-5325, Risk Reduction: 1.523, New Risk: 1.333
2. CVE: CVE-2014-0160, Risk Reduction: 1.169, New Risk: 1.687  
3. CVE: CVE-2018-0734, Risk Reduction: 0.098, New Risk: 2.758
```

Compared with the vulnerability ranking purely based on CVSS base-scores:
  
```bash
1. CVE ID: CVE-2014-0160 | CVSS Score: 7.5 |  Component: openssl (ID: 2)
2. CVE ID: CVE-2016-5325 | CVSS Score: 6.1 |  Component: Node.js (ID: 3)
3. CVE ID: CVE-2018-0734 | CVSS Score: 5.9 |  Component: openssl (ID: 1)
4. CVE ID: CVE-2018-5407 | CVSS Score: 4.7 |  Component: openssl (ID: 1)
5. CVE ID: CVE-2014-0076 | CVSS Score: 2.8 |  Component: openssl (ID: 2)
```

### Scenario 2:

Given a multi-layered network architecture: The External Firewall segregates the Internet from the enterprise's Demilitarized Zone (DMZ), where the Web Server and DNS Server reside. These servers handle external requests while minimizing exposure to the internal network. The Internal Firewall further fortifies the network by safeguarding critical assets within the Internal Subnet, which hosts key components such as the Application Server, Database Server, FTP Server, and Administrative Server. These assets are crucial for the organization’s operations and require stringent protection. Additionally, the User Subnet comprises user workstations that employees use for accessing resources in both the DMZ and Internal Subnets.

<p align="center">
<img src="https://github.com/Yuning-J/VulRG/blob/main/figs/NetworkSample.png" alt="System" width="370px">
</p>

VulRG generates vulnerability ranking for the system. Here is an example of vulnerabilities ranking for the Database Server: 

<p align="center">
<img src="https://github.com/Yuning-J/VulRG/blob/main/figs/SysVulRank.png" alt="System" width="770px">
</p>
