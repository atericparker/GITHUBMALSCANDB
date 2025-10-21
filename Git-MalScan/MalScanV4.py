import sys
import subprocess
import time
import requests
import concurrent.futures
import os
import shutil
import threading
import hashlib
import datetime
from requests.exceptions import RequestException
from timescaledb_ingestor import TimescaleIngestor
import dotenv
dotenv.load_dotenv()


print("Made by Net-Zero also known as NZ0, Check out my github: https://github.com/Net-Zer0")
print("This project is using a MIT license, see LICENSE for more information.")
print("Copyright (c) 2025 NZ0")

# GitHub API token (replace with yours)
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN') # your GitHub API token
VT_API_KEY = os.getenv('VT_API_KEY')  # Your VirusTotal API key
SCANNER_VERSION = "MalScanV4"

# Directories
TEMP_DIR = "temp"
USB_DIR = "ssd"  # Use SSD as USB storage
SSD_DIR = "ssd"

# GitHub search queries and sorting
SEARCH_QUERY = (
    "extension:exe OR extension:com OR extension:pif OR extension:msi OR extension:scr OR extension:bat OR extension:cmd "
    "OR extension:dll OR extension:sys OR extension:drv OR extension:ocx "
    "OR extension:vbs OR extension:js OR extension:ps1 OR extension:hta OR extension:wsf OR extension:lnk OR extension:sh OR extension:py "
    "OR extension:zip OR extension:rar OR extension:7z OR extension:tar OR extension:gz OR extension:iso "
    "OR extension:docm OR extension:xlsm OR extension:pptm "
    "OR extension:apk OR extension:jar"
)
SEARCHES = [
    {"desc": "fewest stars", "sort": "stars", "order": "asc"},
    {"desc": "newly indexed", "sort": "indexed", "order": "desc"},
    {"desc": "recently updated", "sort": "updated", "order": "desc"},
]

PROCESSED_LIST = os.path.join(USB_DIR, "processed_files.txt")
PROCESSED_REPOS_LIST = os.path.join(USB_DIR, "processed_repos.txt")




# Track VirusTotal usage
VT_LOOKUPS = 0
VT_LOOKUPS_LIMIT = 500  # daily quota
VT_LOOKUPS_PER_MIN = 4
VT_LOOKUPS_THIS_MIN = 0
VT_LAST_MINUTE = datetime.datetime.now().minute

def can_use_virustotal():
    global VT_LOOKUPS, VT_LOOKUPS_THIS_MIN, VT_LAST_MINUTE
    now_minute = datetime.datetime.now().minute
    if now_minute != VT_LAST_MINUTE:
        VT_LOOKUPS_THIS_MIN = 0
        VT_LAST_MINUTE = now_minute
    if VT_LOOKUPS >= VT_LOOKUPS_LIMIT:
        print("[VT] Daily VirusTotal quota reached, skipping further scans.")
        return False
    if VT_LOOKUPS_THIS_MIN >= VT_LOOKUPS_PER_MIN:
        print("[VT] Per-minute VirusTotal quota reached, waiting...")
        time.sleep(60 - datetime.datetime.now().second)
        VT_LOOKUPS_THIS_MIN = 0
        VT_LAST_MINUTE = datetime.datetime.now().minute
    return True

def search_git_repos():
    """Search GitHub for repositories by fewest stars, newly indexed, and recently updated."""
    all_items = []
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    for search in SEARCHES:
        print(f"[INFO] Searching GitHub repositories ({search['desc']})...")
        url = (
            f"https://api.github.com/search/repositories"
            f"?q={SEARCH_QUERY}"
            f"&sort={search['sort']}"
            f"&order={search['order']}"
            f"&per_page={per_page}"
        )
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            items = response.json().get("items", [])
            print(f"[INFO] Found {len(items)} repositories for {search['desc']}.")
            all_items.extend(items)
        elif response.status_code == 403:
            print("[ERROR] GitHub API rate limit reached. Sleeping for 5 minutes...")
            time.sleep(300)
            continue
        else:
            print(f"[ERROR] GitHub API Error ({search['desc']}):", response.status_code)
    # Remove duplicates by repo URL
    seen = set()
    unique_items = []
    for item in all_items:
        url = item["html_url"]
        if url not in seen:
            seen.add(url)
            unique_items.append(item)
    print(f"[INFO] Total unique repositories found: {len(unique_items)}")
    return unique_items

def download_file(url, filename):
    if verbose:
        print(f"[INFO] Downloading {filename} from {url} ...")
    os.makedirs(TEMP_DIR, exist_ok=True)
    file_path = os.path.join(TEMP_DIR, filename)

    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(file_path, "wb") as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        if verbose:
            print(f"[INFO] Downloaded: {filename} to {file_path}")
        return file_path
    else:
        if verbose:
            print(f"[ERROR] Download failed: {filename}")
        return None

def scan_with_clamav(file_path):
    """Scan file using ClamAV with verbose output and timing."""
    print(f"[INFO] Scanning {file_path} with ClamAV (verbose)...")
    start = time.time()
    result = subprocess.run(
        ["clamscan", "--verbose", file_path],
        capture_output=True,
        text=True
    )
    elapsed = time.time() - start
    print(f"[INFO] ClamAV output:\n{result.stdout.strip()}")
    print(f"[INFO] Scan time: {elapsed:.2f} seconds")
    if "FOUND" in result.stdout:
        print(f"[WARNING] Malicious file detected: {file_path}")
        return True
    print(f"[INFO] No threats found in: {file_path}")
    return False

def scan_with_clamav_low_priority(file_path):
    print(f"[INFO] Scanning {file_path} with ClamAV (extra low priority)...")
    start = time.time()
    try:
        result = subprocess.run(
            [
                "ionice", "-c3",  # Idle I/O priority
                "nice", "-n", "19",  # Lowest CPU priority
                "clamscan", "--threads=1", file_path  # Single thread, no verbose
            ],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print("[ERROR] clamscan not found on system PATH.")
        return {
            "detected": False,
            "scan_time_ms": None,
            "threats": None,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "error": "clamscan_not_found",
        }

    elapsed = time.time() - start
    stdout = result.stdout.strip()
    stderr = result.stderr.strip()
    print(f"[INFO] ClamAV output:\n{stdout}")
    print(f"[INFO] Scan time: {elapsed:.2f} seconds")

    detected = "FOUND" in stdout
    threats = stdout.count("FOUND") if detected else 0

    if detected:
        print(f"[WARNING] Malicious file detected: {file_path}")
    else:
        print(f"[INFO] No threats found in: {file_path}")

    return {
        "detected": detected,
        "scan_time_ms": int(elapsed * 1000),
        "threats": threats,
        "returncode": result.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "error": None if result.returncode in (0, 1) else f"clamscan_returncode_{result.returncode}",
    }

def save_malicious_file(file_path, file_url):
    if verbose:
        print(f"[INFO] Moving malicious file to SSD: {file_path}")
    if os.path.exists(USB_DIR):
        # Get the base name without extension for the directory
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        dest_dir = os.path.join(USB_DIR, base_name)
        os.makedirs(dest_dir, exist_ok=True)

        # Move the binary into the new directory
        dest_path = os.path.join(dest_dir, os.path.basename(file_path))
        shutil.move(file_path, dest_path)
        if verbose:
            print(f"[INFO] Saved to SSD: {dest_path}")

        # Save the source URL in a text file inside the same directory
        url_txt_path = os.path.join(dest_dir, "source.url.txt")
        with open(url_txt_path, "w") as urlfile:
            urlfile.write(f"{file_url}\n")
        if verbose:
            print(f"[INFO] Wrote source URL to {url_txt_path}")

        # Log to master log file
        with open(os.path.join(USB_DIR, "malicious_files.txt"), "a") as log:
            log.write(f"{dest_path} | Source URL: {file_url}\n")
        if verbose:
            print(f"[INFO] Logged malicious file and source URL.")
    else:
        print("[ERROR] SSD storage not found.")

def mount_ssd():
    if verbose:
        print(f"[INFO] Mounting SSD partition /dev/sda3 to {SSD_DIR} ...")
    os.makedirs(SSD_DIR, exist_ok=True)
    try:
        subprocess.run(["mount", "/dev/sda3", SSD_DIR], check=True)
        if verbose:
            print(f"[INFO] SSD mounted at: {SSD_DIR}")
    except subprocess.CalledProcessError:
        print("[ERROR] Failed to mount SSD. Please check your partition and try again.")

def load_processed():
    """Load processed file URLs from blocklist."""
    if os.path.exists(PROCESSED_LIST):
        with open(PROCESSED_LIST, "r") as f:
            return set(line.strip() for line in f)
    return set()

def add_to_processed(file_url):
    """Add a file URL to the blocklist."""
    with open(PROCESSED_LIST, "a") as f:
        f.write(file_url + "\n")

def load_processed_repos():
    if os.path.exists(PROCESSED_REPOS_LIST):
        with open(PROCESSED_REPOS_LIST, "r") as f:
            return set(line.strip() for line in f)
    return set()

def add_to_processed_repos(repo_full_name):
    with open(PROCESSED_REPOS_LIST, "a") as f:
        f.write(repo_full_name + "\n")

files_processed = 0  # Keep this

# Update MALWARE_EXTENSIONS to include all requested types
MALWARE_EXTENSIONS = [
    # Executable Files
    ".exe", ".com", ".pif", ".msi", ".scr", ".bat", ".cmd",
    # Dynamic & System Files
    ".dll", ".sys", ".drv", ".ocx",
    # Script & Macro Files
    ".vbs", ".ps1", ".hta", ".wsf", ".lnk", 
    # Archive Files
    ".zip", ".rar", ".7z", ".tar", ".gz", ".iso",
    # Office Files with Macros
    ".docm", ".xlsm", ".pptm",
    # Other
    ".apk", ".jar"
]


def compute_sha256(file_path):
    """Compute the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
    except OSError as exc:
        print(f"[ERROR] Failed to hash {file_path}: {exc}")
        return None
    return sha256.hexdigest()

def get_malware_files_in_repo(repo_full_name, token, path="", depth=0, max_depth=3, retries=3):
    headers = {"Authorization": f"token {token}"}
    if depth == 0 and verbose:
        print(f"[INFO] Searching inside {repo_full_name}...")
    if path:
        contents_url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}"
    else:
        contents_url = f"https://api.github.com/repos/{repo_full_name}/contents"
    malware_files = []
    if max_depth != 0 and depth > max_depth:
        return malware_files
    attempt = 0
    while attempt < retries:
        try:
            response = requests.get(contents_url, headers=headers, timeout=15)
            if response.status_code == 200:
                files = response.json()
                for f in files:
                    if f["type"] == "file" and any(f["name"].lower().endswith(ext) for ext in MALWARE_EXTENSIONS):
                        malware_files.append(f)
                    elif f["type"] == "dir":
                        malware_files.extend(get_malware_files_in_repo(repo_full_name, token, f["path"], depth+1, max_depth))
                break
            elif response.status_code == 403:
                print("[ERROR] GitHub API rate limit reached. Sleeping for 5 minutes...")
                time.sleep(300)
                attempt += 1
            else:
                print(f"[ERROR] GitHub API Error: {response.status_code}")
                break
        except RequestException as e:
            print(f"[ERROR] Network error fetching {contents_url}: {e}")
            attempt += 1
            time.sleep(5)
    return malware_files

def list_files_in_dir(path, label):
    print(f"\n[INFO] Listing files in {label} ({path}):")
    if not os.path.exists(path):
        print(f"[WARN] Path does not exist: {path}")
        return
    for root, dirs, files in os.walk(path):
        for name in files:
            print(os.path.join(root, name))
    print("")

def scan_with_virustotal(file_path, file_hash=None):
    """Run a VirusTotal lookup and optionally upload the file if no cached result exists."""
    if not os.path.exists(file_path):
        return {
            "requested": False,
            "counts": None,
            "status": "error",
            "error": "file_missing",
            "sha256": file_hash,
            "analysis_id": None,
        }

    file_hash = file_hash or compute_sha256(file_path)
    headers = {"x-apikey": VT_API_KEY}
    lookup_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    try:
        response = requests.get(lookup_url, headers=headers, timeout=15)
    except RequestException as exc:
        print(f"[VT] Error contacting VirusTotal: {exc}")
        return {
            "requested": True,
            "counts": None,
            "status": "error",
            "error": f"lookup_error:{exc}",
            "sha256": file_hash,
            "analysis_id": None,
        }

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        print(f"[VT] Scan results for {file_path}: {stats}")
        return {
            "requested": True,
            "counts": stats,
            "status": "completed",
            "error": None,
            "sha256": file_hash,
            "analysis_id": None,
        }

    if response.status_code not in (404,):
        print(f"[VT] Hash lookup failed: {response.status_code} {response.text}")
        return {
            "requested": True,
            "counts": None,
            "status": "error",
            "error": f"lookup_status_{response.status_code}",
            "sha256": file_hash,
            "analysis_id": None,
        }

    upload_url = "https://www.virustotal.com/api/v3/files"
    try:
        with open(file_path, "rb") as fh:
            files = {"file": (os.path.basename(file_path), fh)}
            upload_response = requests.post(upload_url, headers=headers, files=files, timeout=60)
    except RequestException as exc:
        print(f"[VT] Error uploading file to VirusTotal: {exc}")
        return {
            "requested": True,
            "counts": None,
            "status": "error",
            "error": f"upload_error:{exc}",
            "sha256": file_hash,
            "analysis_id": None,
        }

    if upload_response.status_code != 200:
        print(f"[VT] Error uploading file to VirusTotal: {upload_response.status_code}")
        return {
            "requested": True,
            "counts": None,
            "status": "error",
            "error": f"upload_status_{upload_response.status_code}",
            "sha256": file_hash,
            "analysis_id": None,
        }

    print(f"[VT] File uploaded to VirusTotal for scanning: {file_path}")
    analysis_id = upload_response.json()["data"]["id"]
    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    for attempt in range(12):  # Wait up to ~60 seconds
        time.sleep(5)
        try:
            analysis_response = requests.get(analysis_url, headers=headers, timeout=15)
        except RequestException as exc:
            print(f"[VT] Error polling analysis: {exc}")
            return {
                "requested": True,
                "counts": None,
                "status": "error",
                "error": f"poll_error:{exc}",
                "sha256": file_hash,
                "analysis_id": analysis_id,
            }
        if analysis_response.status_code == 200:
            analysis_data = analysis_response.json()
            status = analysis_data["data"]["attributes"]["status"]
            if status == "completed":
                stats = analysis_data["data"]["attributes"]["stats"]
                print(f"[VT] Scan results for {file_path}: {stats}")
                return {
                    "requested": True,
                    "counts": stats,
                    "status": "completed",
                    "error": None,
                    "sha256": file_hash,
                    "analysis_id": analysis_id,
                }
            print(f"[VT] Waiting for scan results... ({status})")
        else:
            print(f"[VT] Error polling analysis: {analysis_response.status_code}")
            break

    print("[VT] Timed out waiting for scan results.")
    return {
        "requested": True,
        "counts": None,
        "status": "timeout",
        "error": "analysis_timeout",
        "sha256": file_hash,
        "analysis_id": analysis_id,
    }


def determine_outcome(clamav_detected, vt_counts, vt_status, vt_error, clamav_error):
    if clamav_detected:
        return "infected"
    if vt_counts:
        if vt_counts.get("malicious", 0) > 0:
            return "infected"
        if vt_counts.get("suspicious", 0) > 0:
            return "suspicious"
        return "clean"
    if clamav_error:
        return "error"
    if vt_status == "timeout":
        return "timeout"
    if vt_error:
        return "error"
    return "unknown"

if __name__ == "__main__":
    # Parameter prompts (no menu)
    delete_blocklist = input("Delete blocklist and re-scan all files? (y/N): ").strip().lower()
    if delete_blocklist == "y":
        if os.path.exists(PROCESSED_LIST):
            os.remove(PROCESSED_LIST)
            print("[INFO] Blocklist for files deleted.")
        else:
            print("[INFO] No file blocklist found to delete.")
        if os.path.exists(PROCESSED_REPOS_LIST):
            os.remove(PROCESSED_REPOS_LIST)
            print("[INFO] Blocklist for repos deleted.")
        else:
            print("[INFO] No repo blocklist found to delete.")

    recursion_mode = input("Scan recursively through all folders? (Y/n): ").strip().lower()
    if recursion_mode == "y":
        try:
            max_depth = int(input("Enter max folder recursion depth (recommended: 2-3, 0 for unlimited): ").strip())
        except ValueError:
            max_depth = 3
            print("[INFO] Invalid input, using recommended max depth: 3")
        if max_depth < 0:
            max_depth = 3
            print("[INFO] Negative depth not allowed, using recommended max depth: 3")
    else:
        max_depth = 1  # Only scan root directory

    try:
        per_page = int(input("How many repositories per search page? (recommended: 30, max: 100): ").strip())
        if per_page < 1 or per_page > 100:
            print("[INFO] per_page out of range, using 30.")
            per_page = 30
    except ValueError:
        per_page = 30
        print("[INFO] Invalid input, using recommended per_page: 30")

    if len(sys.argv) > 1:
        KEYWORD = sys.argv[1]
        print(f"[INFO] Using keyword: {KEYWORD}")
    else:
        KEYWORD = input("Enter a keyword to search for (Leave blank to not specify a topic, this will scan malware with common extension on a particular topic): ").strip()
        if KEYWORD:
            print(f"[INFO] Using keyword: {KEYWORD}")
        else:
            print("[INFO] No keyword specified, searching all malware files with common extensions.")

    if KEYWORD:
        SEARCH_QUERY = KEYWORD
    else:
        SEARCH_QUERY = "extension:exe"

    verbose = input("Show all status and verbose output? (y/N): ").strip().lower() == "y"

    ingestor = TimescaleIngestor.from_env()
    if not ingestor:
        print("[INFO] TimescaleDB ingestion disabled for this session.")

    # Track VirusTotal usage
    VT_LOOKUPS = 0
    VT_LOOKUPS_LIMIT = 500  # daily quota
    VT_LOOKUPS_PER_MIN = 4
    VT_LOOKUPS_THIS_MIN = 0
    VT_LAST_MINUTE = datetime.datetime.now().minute

    if verbose:
        print("[INFO] Starting RaspiAutoMalwareScanner...")
    mount_ssd()
    processed = load_processed()
    processed_repos = load_processed_repos()
    files_processed = 0
    try:
        while True:
            repos = search_git_repos()
            for repo in repos:
                repo_full_name = repo["full_name"]
                if repo_full_name in processed_repos:
                    if verbose:
                        print(f"[INFO] Skipping already processed repo: {repo_full_name}")
                    continue

                repo_id = None
                if ingestor:
                    repo_id = ingestor.get_or_create_repo(repo_full_name)
                    if repo_id is not None:
                        notes = f"github_id={repo.get('id')} stars={repo.get('stargazers_count')} default_branch={repo.get('default_branch')}"
                        ingestor.log_repo_check(repo_id, notes=notes)

                malware_files = get_malware_files_in_repo(repo_full_name, GITHUB_TOKEN, "", 0, max_depth)
                for malware_file in malware_files:
                    file_url = malware_file["download_url"]
                    filename = malware_file["name"]
                    repo_relative_path = malware_file.get("path", filename)
                    if file_url in processed:
                        continue
                    processed.add(file_url)
                    add_to_processed(file_url)
                    print(f"[INFO] Processing file: {filename} from {file_url}")
                    file_path = download_file(file_url, filename)
                    file_sha256 = None
                    file_size = None
                    vt_counts = None
                    vt_status = None
                    vt_error = None
                    vt_analysis_id = None
                    vt_requested = False

                    if file_path:
                        file_sha256 = compute_sha256(file_path)
                        try:
                            file_size = os.path.getsize(file_path)
                        except OSError:
                            file_size = None

                        clamav_scan = scan_with_clamav_low_priority(file_path)
                        clamav_detected = clamav_scan.get("detected", False)
                        clamav_scantime_ms = clamav_scan.get("scan_time_ms")
                        clamav_threats = clamav_scan.get("threats")
                        clamav_error = clamav_scan.get("error")

                        if clamav_detected:
                            print("[CLAMAV] Threat detected by ClamAV.")
                        else:
                            if can_use_virustotal():
                                vt_summary = scan_with_virustotal(file_path, file_sha256)
                                vt_requested = vt_summary.get("requested", False)
                                if vt_requested:
                                    VT_LOOKUPS += 1
                                    VT_LOOKUPS_THIS_MIN += 1
                                vt_counts = vt_summary.get("counts")
                                vt_status = vt_summary.get("status")
                                vt_error = vt_summary.get("error")
                                vt_analysis_id = vt_summary.get("analysis_id")
                                file_sha256 = vt_summary.get("sha256") or file_sha256
                                if vt_counts and (vt_counts.get("malicious", 0) > 0 or vt_counts.get("suspicious", 0) > 0):
                                    print("[VT] VirusTotal detected malicious or suspicious file!")
                            else:
                                vt_error = "vt_quota_reached"
                                print("[VT] VirusTotal quota reached; skipping scan.")

                        outcome = determine_outcome(clamav_detected, vt_counts, vt_status, vt_error, clamav_error)
                        vt_detected = bool(
                            vt_counts and (vt_counts.get("malicious", 0) > 0 or vt_counts.get("suspicious", 0) > 0)
                        )

                        metadata = {
                            "download_url": file_url,
                            "file_size": file_size,
                            "repo_html_url": repo.get("html_url"),
                            "repo_default_branch": repo.get("default_branch"),
                            "repo_id": repo.get("id"),
                            "vt_status": vt_status,
                            "vt_analysis_id": vt_analysis_id,
                            "clamav": {
                                "returncode": clamav_scan.get("returncode"),
                                "error": clamav_error,
                                "stdout": clamav_scan.get("stdout"),
                                "stderr": clamav_scan.get("stderr"),
                            },
                        }

                        if ingestor and repo_id:
                            ingestor.log_scan(
                                repo_id=repo_id,
                                checked_at=datetime.datetime.now(datetime.timezone.utc),
                                file_path=repo_relative_path,
                                sha256=file_sha256,
                                scanner_version=SCANNER_VERSION,
                                metadata=metadata,
                                vt_counts=vt_counts,
                                vt_requested=vt_requested,
                                vt_error=vt_error,
                                clamav_threats=clamav_threats,
                                clamav_scantime_ms=clamav_scantime_ms,
                                outcome=outcome,
                            )

                        if clamav_detected or vt_detected:
                            save_malicious_file(file_path, file_url)
                        else:
                            try:
                                os.remove(file_path)
                                if verbose:
                                    print(f"[INFO] Deleted file after scan: {file_path}")
                            except Exception as e:
                                print(f"[ERROR] Failed to delete {file_path}: {e}")
                    files_processed += 1
                    print(f"[INFO] Total files processed: {files_processed}")
                # Always add repo to processed_repos after scanning all its files
                add_to_processed_repos(repo_full_name)
                processed_repos.add(repo_full_name)
            print("[INFO] Finished checking all repositories, sleeping before next search...")
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user. Exiting cleanly.")
    finally:
        if ingestor:
            ingestor.close()
