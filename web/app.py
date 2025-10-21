#!/usr/bin/env python3
"""
Web frontend for exploring GitHub malware scan data from TimescaleDB.
"""
import os
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

# Database connection
def get_db_connection():
    return psycopg2.connect(
        dbname=os.getenv('POSTGRES_DATABASE'),
        user=os.getenv('POSTGRES_USERNAME'),
        password=os.getenv('POSTGRES_PASSWORD'),
        host=os.getenv('POSTGRES_HOSTNAME'),
        port=os.getenv('POSTGRES_PORT'),
        sslmode='require'
    )

# Routes
@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    """Get overall statistics"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    stats = {}

    # Total repositories
    cur.execute("SELECT COUNT(DISTINCT repo_id) as count FROM repositories")
    stats['total_repos'] = cur.fetchone()['count']

    # Total scans
    cur.execute("SELECT COUNT(*) as count FROM scan_log")
    stats['total_scans'] = cur.fetchone()['count']

    # Scans by outcome
    cur.execute("""
        SELECT outcome, COUNT(*) as count
        FROM scan_log
        GROUP BY outcome
        ORDER BY count DESC
    """)
    stats['by_outcome'] = cur.fetchall()

    # Infected files
    cur.execute("SELECT COUNT(*) as count FROM scan_log WHERE outcome = 'infected'")
    stats['infected_count'] = cur.fetchone()['count']

    # Suspicious files
    cur.execute("SELECT COUNT(*) as count FROM scan_log WHERE outcome = 'suspicious'")
    stats['suspicious_count'] = cur.fetchone()['count']

    # Clean files
    cur.execute("SELECT COUNT(*) as count FROM scan_log WHERE outcome = 'clean'")
    stats['clean_count'] = cur.fetchone()['count']

    # Recent scans (last 24 hours)
    cur.execute("""
        SELECT COUNT(*) as count
        FROM scan_log
        WHERE checked_at > NOW() - INTERVAL '24 hours'
    """)
    stats['recent_scans_24h'] = cur.fetchone()['count']

    # Most scanned repos
    cur.execute("""
        SELECT r.repo_name, COUNT(*) as scan_count
        FROM scan_log s
        JOIN repositories r ON s.repo_id = r.repo_id
        GROUP BY r.repo_name
        ORDER BY scan_count DESC
        LIMIT 10
    """)
    stats['top_repos'] = cur.fetchall()

    # Scans over time (last 7 days)
    cur.execute("""
        SELECT DATE(checked_at) as date, COUNT(*) as count
        FROM scan_log
        WHERE checked_at > NOW() - INTERVAL '7 days'
        GROUP BY DATE(checked_at)
        ORDER BY date ASC
    """)
    stats['scans_timeline'] = cur.fetchall()

    # Average ClamAV scan time
    cur.execute("""
        SELECT AVG(clamav_scantime_ms) as avg_time
        FROM scan_log
        WHERE clamav_scantime_ms IS NOT NULL
    """)
    avg_time = cur.fetchone()['avg_time']
    stats['avg_clamav_scantime_ms'] = round(float(avg_time), 2) if avg_time else 0

    # VirusTotal usage
    cur.execute("SELECT COUNT(*) as count FROM scan_log WHERE vt_requested = true")
    stats['vt_requests'] = cur.fetchone()['count']

    cur.close()
    conn.close()

    return jsonify(stats)

@app.route('/api/repositories')
def get_repositories():
    """Get list of repositories with scan counts"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    offset = (page - 1) * per_page

    cur.execute("""
        SELECT
            r.repo_id,
            r.repo_name,
            COUNT(s.repo_id) as total_scans,
            SUM(CASE WHEN s.outcome = 'infected' THEN 1 ELSE 0 END) as infected,
            SUM(CASE WHEN s.outcome = 'suspicious' THEN 1 ELSE 0 END) as suspicious,
            SUM(CASE WHEN s.outcome = 'clean' THEN 1 ELSE 0 END) as clean,
            MAX(s.checked_at) as last_scan
        FROM repositories r
        LEFT JOIN scan_log s ON r.repo_id = s.repo_id
        GROUP BY r.repo_id, r.repo_name
        ORDER BY total_scans DESC, r.repo_name ASC
        LIMIT %s OFFSET %s
    """, (per_page, offset))

    repos = cur.fetchall()

    # Get total count
    cur.execute("SELECT COUNT(*) as count FROM repositories")
    total = cur.fetchone()['count']

    cur.close()
    conn.close()

    return jsonify({
        'repositories': repos,
        'page': page,
        'per_page': per_page,
        'total': total,
        'pages': (total + per_page - 1) // per_page
    })

@app.route('/api/scans')
def get_scans():
    """Get list of scans with filters"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    outcome = request.args.get('outcome', None)
    repo_id = request.args.get('repo_id', None, type=int)
    offset = (page - 1) * per_page

    where_clauses = []
    params = []

    if outcome:
        where_clauses.append("s.outcome = %s")
        params.append(outcome)

    if repo_id:
        where_clauses.append("s.repo_id = %s")
        params.append(repo_id)

    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    query = f"""
        SELECT
            s.*,
            r.repo_name
        FROM scan_log s
        JOIN repositories r ON s.repo_id = r.repo_id
        {where_sql}
        ORDER BY s.checked_at DESC
        LIMIT %s OFFSET %s
    """
    params.extend([per_page, offset])

    cur.execute(query, params)
    scans = cur.fetchall()

    # Get total count
    count_query = f"SELECT COUNT(*) as count FROM scan_log s {where_sql}"
    cur.execute(count_query, params[:-2])
    total = cur.fetchone()['count']

    cur.close()
    conn.close()

    return jsonify({
        'scans': scans,
        'page': page,
        'per_page': per_page,
        'total': total,
        'pages': (total + per_page - 1) // per_page
    })

@app.route('/api/scan/<int:scan_id>')
def get_scan_detail(scan_id):
    """Get detailed information about a specific scan"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
        SELECT s.*, r.repo_name
        FROM scan_log s
        JOIN repositories r ON s.repo_id = r.repo_id
        WHERE s.scan_id = %s
    """, (scan_id,))

    scan = cur.fetchone()

    cur.close()
    conn.close()

    if scan:
        return jsonify(scan)
    else:
        return jsonify({'error': 'Scan not found'}), 404

@app.route('/api/search')
def search():
    """Search repositories and scans"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({'repositories': [], 'scans': []})

    # Search repositories
    cur.execute("""
        SELECT r.repo_id, r.repo_name, COUNT(s.repo_id) as scan_count
        FROM repositories r
        LEFT JOIN scan_log s ON r.repo_id = s.repo_id
        WHERE r.repo_name ILIKE %s
        GROUP BY r.repo_id, r.repo_name
        ORDER BY scan_count DESC
        LIMIT 20
    """, (f'%{query}%',))
    repos = cur.fetchall()

    # Search scans by file path or SHA256
    cur.execute("""
        SELECT s.*, r.repo_name
        FROM scan_log s
        JOIN repositories r ON s.repo_id = r.repo_id
        WHERE s.file_path ILIKE %s OR s.sha256 ILIKE %s
        ORDER BY s.checked_at DESC
        LIMIT 20
    """, (f'%{query}%', f'%{query}%'))
    scans = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify({
        'repositories': repos,
        'scans': scans
    })

@app.route('/api/file/<sha256>')
def get_file_by_hash(sha256):
    """Get all scans for a specific file hash"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("""
        SELECT s.*, r.repo_name
        FROM scan_log s
        JOIN repositories r ON s.repo_id = r.repo_id
        WHERE s.sha256 = %s
        ORDER BY s.checked_at DESC
    """, (sha256,))

    scans = cur.fetchall()

    cur.close()
    conn.close()

    return jsonify({'scans': scans})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
