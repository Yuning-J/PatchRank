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
  <img src="https://img.shields.io/github/license/Yuning-J/PatchRank?style=for-the-badge" alt="License" height="25">
  <br />
  
  <h3 align="center"> PatchRank: Multi-Level Explainable Vulnerability Patch Ranking</h3>
  <p align="center">
   This project presents a comprehensive framework for risk aggregation and vulnerability prioritization tailored for complex systems, such as industrial control systems (ICS), IoT environments, and enterprise networks. Our method employs a graph-based approach to model system dependencies and attack paths, enabling a multi-level analysis that captures both asset and component-level risks.
 
  </p>
</p>

## Getting Started:

- Setup Instructions: Clone the project; Create a virtual environment, also change the absolute path in the conf.py file; Install requirements using `pip`:
```bash
pip install -r requirements.txt
```

## Usage Guide: 
Use main.py to compute asset-level or system-wide risk aggregation and vulnerability ranking. The user can customize the analysis by specifying the level of aggregation, the input data file, and whether to rank vulnerabilities based solely on CVSS base scores.

**Example Command**
```bash
python main.py --level system --data paper_ICS.json
python main.py --level system --data paper_ES.json
python main.py --level asset --data paper_openPLC.json
```

**Command-line arguments**
- --level: (Required) Specify the analysis level: asset (default) or system.
- --data: (Required) Filename of the data to be processed. The data file must be located in the conf.asset_vul_data_path.
- --cvss_only: (Optional) Include this flag to rank vulnerabilities based only on CVSS base scores.

## Application Scenario:

### Scenario 1:
Given an OpenPLC with the following configuration:

<p align="center">
<img src="https://github.com/Yuning-J/VulRG/blob/main/figs/openPLC.png" alt="System" width="250px">
</p>

The expected outcome for asset risk calculation and TOP-3 vulnerability ranking using our VulRG are:
  
```bash
Initial Asset Risk: 2.8561
Initial Component Risks: [0.8539847731590271, 1.0191421508789062, 0.9118924736976624, 0.0, 0.0]

CVE-2016-5325 —> patched asset risk is 1.333
—> Scope changed is True and utilized Ransomware is 0
—> CVSS is 6.1, with likelihood as 2.8 and impact as 2.7
—> EPSS score is 0.00437
—> existing exploit is 0
—> exists in Component 3

CVE-2014-0160 —> patched asset risk is 1.687
—> Scope changed is False and utilized Ransomware is 0
—> CVSS is 7.5, with likelihood as 3.9 and impact as 3.6
—> EPSS score is 0.97354
—> existing exploit is 1
—> exists in Component 2

CVE-2018-0734 —> patched asset risk is 2.758
—> Scope changed is False and utilized Ransomware is 0
—> CVSS is 5.9, with likelihood as 2.2 and impact as 3.6
—> EPSS score is 0.00342
—> existing exploit is 0
—> exists in Component 1
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
