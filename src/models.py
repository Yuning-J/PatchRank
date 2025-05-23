class Vulnerability:
    def __init__(self, 
                 cve_id: str = "", 
                 cvss: float = 0.0, 
                 cvssV3Vector: str = "", 
                 scopeChanged: bool = False, 
                 likelihood: float = 0.0, 
                 impact: float = 0.0, 
                 exploit: bool = False, 
                 epss: float = 0.0, 
                 ransomWare: bool = False,
                 component_id: str = ""):
        self.cve_id = cve_id
        self.cvss = cvss
        self.cvssV3Vector = cvssV3Vector 
        self.scopeChanged = scopeChanged
        self.likelihood = likelihood
        self.impact = impact
        self.exploit = exploit
        self.epss = epss
        self.ransomWare = ransomWare
        self.propagation_likehood = None
        self.direct_risk = None
        self.component_id = component_id

    def __repr__(self):
        return f"Vulnerability(cve_id={self.cve_id}, cvss={self.cvss})"


class Component:
    def __init__(self, 
                 comp_id: str = "", 
                 comp_type: str = "", 
                 vendor: str = "", 
                 name: str = "", 
                 version: str = "", 
                 embedded_in: str = None):
        self.id = comp_id
        self.type = comp_type
        self.vendor = vendor
        self.name = name
        self.version = version
        self.embedded_in = embedded_in
        self.vulnerabilities = []  # Empty list for vulnerabilities

    def add_vulnerability(self, vulnerability: Vulnerability):
        self.vulnerabilities.append(vulnerability)

    def __repr__(self):
        return f"Component(id={self.id}, name={self.name}, version={self.version})"


class Asset:
    def __init__(self, 
                 asset_id: str = "", 
                 asset_type: str = "", 
                 name: str = "", 
                 criticality_level: int = 0, 
                 ip_address: str = "0.0.0.0", 
                 mac_address: str = "00:00:00:00:00:00"):
        self.asset_id = asset_id
        self.type = asset_type
        self.name = name
        self.criticality_level = criticality_level
        self.updated_criticality = criticality_level
        self.final_criticality = criticality_level
        self.total_propagation_risk = 0
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.components = []  # Empty list for components
        self.adjacency_matrix = []  # Empty list for adjacency matrix
        self.vulnerabilities = []

    def add_component(self, component: Component):
        self.components.append(component)

    def set_adjacency_matrix(self, adjacency_matrix: list):
        self.adjacency_matrix = adjacency_matrix

    def __repr__(self):
        return f"Asset(id={self.asset_id}, name={self.name}, criticality={self.criticality_level})"


class System:
    def __init__(self):
        self.assets = []  # Empty list for assets
        self.connections = []

    def add_asset(self, asset: Asset):
        self.assets.append(asset)

    def add_connection(self, connection):
        self.connections.append(connection)     

    def __repr__(self):
        return f"System(assets={len(self.assets)})"
