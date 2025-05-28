import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import './App.css';

// Import the VulnerabilityRankingUI component
// Note: You'll need to create this component in the components folder
import VulnerabilityRankingUI from './components/VulnerabilityRankingUI';

// Configuration for the API
const API_URL = 'http://localhost:5000/api';

function App() {
  return (
    <Router>
      <div className="App">
        <header className="App-header">
          <div className="container">
            <h1>Vulnerability Risk Analysis</h1>
            <nav>
              <ul>
                <li><Link to="/">Home</Link></li>
                <li><Link to="/about">About</Link></li>
              </ul>
            </nav>
          </div>
        </header>

        <main className="container">
          <Routes>
            <Route path="/" element={<VulnerabilityRankingUI apiUrl={API_URL} />} />
            <Route path="/about" element={<About />} />
          </Routes>
        </main>

        <footer>
          <div className="container">
            <p>© 2025 Vulnerability Risk Analysis System</p>
          </div>
        </footer>
      </div>
    </Router>
  );
}

function About() {
  return (
    <div className="about-page">
      <h2>About This Project</h2>
      <p>This tool analyzes vulnerabilities in assets or systems and provides risk scores and patch prioritization recommendations.</p>

      <div className="section">
        <h3>Risk Calculation Factors</h3>
        <p>The analysis takes into account multiple factors, including:</p>
        <ul>
          <li><strong>Vulnerability CVSS scores</strong> - Common Vulnerability Scoring System metrics</li>
          <li><strong>Component centrality</strong> - How central a component is in the system architecture</li>
          <li><strong>Existing exploits</strong> - Whether known exploits exist for a vulnerability</li>
          <li><strong>Propagation likelihood</strong> - Probability of attack spreading to other components</li>
          <li><strong>EPSS scores</strong> - Exploit Prediction Scoring System metrics</li>
          <li><strong>Impact on critical assets</strong> - Effect on business-critical components</li>
        </ul>
      </div>

      <div className="section">
        <h3>Patch Prioritization</h3>
        <p>The system recommends which vulnerabilities to patch first based on:</p>
        <ul>
          <li>Maximum risk reduction for minimal effort</li>
          <li>Presence of active exploits in the wild</li>
          <li>Impact on system-wide risk</li>
          <li>Potential for ransomware or scope escalation</li>
        </ul>
      </div>

      <div className="section">
        <h3>Usage</h3>
        <p>To use this tool:</p>
        <ol>
          <li>Select between asset-level or system-level analysis</li>
          <li>Choose a configuration file containing vulnerability data</li>
          <li>Run the analysis</li>
          <li>Review results and patch recommendations</li>
        </ol>
      </div>
    </div>
  );
}

export default App;