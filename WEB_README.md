# GitHub Malware Scanner - Web Dashboard

A modern web frontend for exploring malware scan data stored in TimescaleDB.

## Features

- **Real-time Dashboard**: View statistics on scanned repositories, infected files, and scan outcomes
- **Repository Browser**: Browse all scanned repositories with detailed metrics
- **Scan History**: View detailed scan results with filtering by outcome (infected, suspicious, clean, etc.)
- **Search**: Search for repositories, file paths, or SHA256 hashes
- **Timeline Visualization**: See scan activity over the last 7 days
- **Dark Mode UI**: Modern, GitHub-inspired dark interface

## Quick Start

### Prerequisites

- Python 3.8 or higher
- Access to the TimescaleDB database (credentials in `.env`)

### Launch

Simply run the launch script:

```bash
./launch-web.sh
```

The script will:
1. Check for required dependencies
2. Create a Python virtual environment (if needed)
3. Install required packages
4. Launch the Flask web server

Once started, open your browser to:
```
http://localhost:5000
```

Press `Ctrl+C` to stop the server.

## Manual Setup

If you prefer to set up manually:

```bash
cd web
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

## API Endpoints

The backend provides several REST API endpoints:

- `GET /api/stats` - Overall statistics and metrics
- `GET /api/repositories` - List repositories with pagination
- `GET /api/scans` - List scans with filtering and pagination
- `GET /api/scan/<id>` - Get detailed scan information
- `GET /api/search?q=<query>` - Search repositories and scans
- `GET /api/file/<sha256>` - Get all scans for a specific file hash

## Database Schema

The application queries three main tables:

1. **repositories**: Stores repository information
   - `repo_id` - Unique identifier
   - `repo_name` - Full repository name (owner/repo)

2. **repo_log**: Logs when repositories are checked
   - `checked_at` - Timestamp
   - `repo_id` - Reference to repository
   - `notes` - Additional metadata

3. **scan_log**: Stores detailed scan results
   - `scan_id` - Unique identifier
   - `repo_id` - Repository reference
   - `file_path` - Path to scanned file
   - `sha256` - File hash
   - `outcome` - Scan result (infected, suspicious, clean, error, etc.)
   - `vt_counts` - VirusTotal detection counts (JSON)
   - `clamav_threats` - Number of threats detected by ClamAV
   - `metadata` - Additional scan metadata (JSON)

## Configuration

Database credentials are read from the `.env` file in the project root:

```
POSTGRES_USERNAME=tsdbadmin
POSTGRES_PASSWORD=your_password
POSTGRES_DATABASE=tsdb
POSTGRES_HOSTNAME=your_hostname.tsdb.cloud.timescale.com
POSTGRES_PORT=31116
```

## Tech Stack

- **Backend**: Flask (Python)
- **Database**: TimescaleDB (PostgreSQL)
- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Styling**: Custom CSS with GitHub dark theme inspiration

## Development

To run in development mode with auto-reload:

```bash
cd web
export FLASK_ENV=development
python3 app.py
```

## License

MIT License - See main project LICENSE file
