
## Project Structure
```
VulRG/
├── .venv/             # Python virtual environment
├── data/              # Configuration and input data files
│   ├── paper_openPLC.json
│   ├── paper_ICS.json
│   └── ... (other data files)
├── figs/              # Figures and output visualizations
├── output/            # Analysis output directory
├── src/               # Python source code
│   ├── cal_dependence.py
│   ├── conf.py
│   ├── data_processing.py
│   ├── ... (other Python modules)
├── UI/                # User Interface
│   ├── API.py         # Flask API
│   ├── frontend/      # React frontend
│       ├── src/
│       │   ├── components/
│       │   │   └── VulnerabilityRankingUI.js
│       ├── package.json
│       └── build/     # Production build
└── README.md
```

## Prerequisites
- Python 3.8+
- Node.js 16+
- pip (Python package manager)
- npm (Node package manager)

## Backend Setup

### 1. Clone the Repository

### 2. Create and Activate Virtual Environment
```bash
# On Windows
python -m venv .venv
.venv\Scripts\activate

# On macOS/Linux
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Python Dependencies
```bash
pip install -r requirements.txt
```

## Frontend Setup

### 1. Navigate to Frontend Directory
```bash
cd UI/frontend
```

### 2. Install Node Dependencies
```bash
npm install
```

### 3. Available Scripts
- `npm start`: Runs the app in development mode
- `npm run build`: Builds the app for production
- `npm test`: Runs test suites

## Running the Application

### Backend (Flask API)
```bash
# From project root
python UI/API.py
```

### Frontend (React)
```bash
# From frontend directory
npm start
```

## Configuration
- Modify `src/conf.py` to change data paths
- Update configuration files in `data/assets_withVul_data` directory


## Supported Analysis Types
1. Asset-Level analysis that focuses on vulnerabilities within a single asset

2. System-Level analysis that examines vulnerabilities across multiple connected assets


## Virtual Patching
- Simulate vulnerability patches
- Observe real-time risk reduction
- Compare original and current system risks

