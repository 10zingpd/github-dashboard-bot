import requests
from datetime import datetime, timedelta, timezone
import gspread
from google.oauth2.service_account import Credentials
import os

# === CONFIGURATION ===
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")  # <-- Set this as an environment variable
if not GITHUB_TOKEN:
    raise ValueError("GITHUB_TOKEN environment variable is not set. Please set it before running the script.")
ORG_NAMES = ["viamrobotics", "viam-labs", "viam-modules"]  # <-- List of GitHub org names to check
DAYS_THRESHOLD = 3
GOOGLE_SHEETS_ID = "1Zq-tAWF_Y4sgsx3mUahuhamSrvnlgTsOKyBFh4b9nAI"  # <-- Google Sheets spreadsheet ID
GOOGLE_SHEETS_TAB_NAME = "stale_prs"  # <-- Name of the tab/sheet for stale external PRs
DEPENDABOT_TAB_NAME = "bot_alerts"  # <-- Name of the tab/sheet for dependabot and GitHub Actions PRs
EXTERNAL_PRS_TAB_NAME = "external_prs"  # <-- Name of the tab/sheet for all external PRs
MISSING_LICENSE_TAB_NAME = "missing_license"  # <-- Name of the tab/sheet for repos without licenses
GOOGLE_CREDENTIALS_FILE = "credentials.json"  # <-- Path to Google service account credentials JSON file

# === AUTH SETUP ===
headers = {
    "Authorization": f"token {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json"
}

def is_external(pr_user_login, org_logins):
    return pr_user_login not in org_logins

def get_org_members(org):
    url = f"https://api.github.com/orgs/{org}/members"
    members = []
    page = 1
    while True:
        response = requests.get(url, headers=headers, params={"per_page": 100, "page": page})
        if not response.ok:
            break
        batch = response.json()
        if not batch:
            break
        members.extend([m["login"] for m in batch])
        page += 1
    return set(members)

def get_repos(org):
    url = f"https://api.github.com/orgs/{org}/repos"
    repos = []
    page = 1
    while True:
        response = requests.get(url, headers=headers, params={"per_page": 100, "page": page})
        if not response.ok:
            break
        batch = response.json()
        if not batch:
            break
        repos.extend([r["name"] for r in batch])
        page += 1
    return repos

def get_repos_with_license_info(org):
    """Get all repos with their license information."""
    url = f"https://api.github.com/orgs/{org}/repos"
    repos = []
    page = 1
    while True:
        response = requests.get(url, headers=headers, params={"per_page": 100, "page": page})
        if not response.ok:
            break
        batch = response.json()
        if not batch:
            break
        repos.extend(batch)
        page += 1
    return repos

def get_repos_missing_licenses(orgs):
    """Find all public repositories across organizations that are missing licenses (excluding archived repos)."""
    repos_missing_license = []
    for org in orgs:
        print(f"Checking licenses for repos in {org}...")
        repos = get_repos_with_license_info(org)
        for repo in repos:
            # Skip archived repositories
            if repo.get("archived", False):
                continue
            # Skip private repositories (only include public repos)
            if repo.get("private", True):
                continue
            # Check if license is None or null
            if not repo.get("license") or repo["license"] is None:
                repos_missing_license.append({
                    "Organization": org,
                    "Repository": repo["name"],
                    "URL": repo["html_url"],
                    "Description": repo.get("description", "") or "",
                    "Created At (UTC)": repo.get("created_at", ""),
                    "Updated At (UTC)": repo.get("updated_at", "")
                })
        public_non_archived_missing = len([r for r in repos if not r.get("archived", False) and not r.get("private", True) and not r.get("license")])
        print(f"  Found {public_non_archived_missing} public, non-archived repos without licenses")
    return repos_missing_license

def get_stale_external_prs(org, repos, org_members, days_threshold):
    dependabot_prs = []
    other_prs = []  # Stale PRs (includes both org members and external, older than threshold)
    all_external_prs = []  # All external PRs (no threshold, excluding bots and org members)
    cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_threshold)

    for repo in repos:
        url = f"https://api.github.com/repos/{org}/{repo}/pulls"
        response = requests.get(url, headers=headers, params={"state": "open", "per_page": 100})
        if not response.ok:
            continue
        for pr in response.json():
            created_at = datetime.strptime(pr["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            user_login = pr["user"]["login"]
            
            pr_data = {
                "org": org,
                "repo": repo,
                "title": pr["title"],
                "url": pr["html_url"],
                "author": user_login,
                "created_at": pr["created_at"],
                "severity": ""  # Will be populated for dependabot PRs
            }
            
            if user_login == "dependabot[bot]" or user_login == "github-actions[bot]":
                # Include ALL dependabot and GitHub Actions PRs
                if user_login == "dependabot[bot]":
                    # Fetch full PR details to extract severity for display
                    pr_detail_url = f"https://api.github.com/repos/{org}/{repo}/pulls/{pr['number']}"
                    pr_detail_response = requests.get(pr_detail_url, headers=headers)
                    if pr_detail_response.ok:
                        pr_detail = pr_detail_response.json()
                        # Get all label names
                        all_labels = [label.get("name", "") for label in pr_detail.get("labels", [])]
                        labels_lower = [label.lower() for label in all_labels]
                        
                        # Extract severity from labels for display
                        severity = ""
                        if any("critical" in label for label in labels_lower):
                            severity = "Critical"
                        elif any("high" in label for label in labels_lower):
                            severity = "High"
                        elif any("medium" in label for label in labels_lower):
                            severity = "Medium"
                        elif any("low" in label for label in labels_lower):
                            severity = "Low"
                        
                        pr_data["severity"] = severity if severity else "N/A"
                        dependabot_prs.append(pr_data)
                    else:
                        # If we can't fetch details, include PR without severity
                        pr_data["severity"] = "N/A"
                        dependabot_prs.append(pr_data)
                else:
                    # Include all GitHub Actions PRs (no severity)
                    pr_data["severity"] = "N/A"
                    dependabot_prs.append(pr_data)
            else:
                # For stale_prs: include ALL PRs (org members + external) that are older than threshold
                if created_at < cutoff_date:
                    other_prs.append(pr_data)
                
                # For external_prs: only include external contributors (not org members)
                if is_external(user_login, org_members):
                    all_external_prs.append(pr_data)
    return dependabot_prs, other_prs, all_external_prs

def export_prs_to_tab(prs, spreadsheet_id, sheet_name, credentials_file, include_type_column=True):
    """Export a list of items (PRs, repos, etc.) to a specific Google Sheets tab."""
    if not prs:
        print(f"\n⚠️  No items to export to '{sheet_name}' tab.\n")
        return
    
    try:
        # Authenticate with Google Sheets
        scope = ['https://spreadsheets.google.com/feeds',
                 'https://www.googleapis.com/auth/drive']
        creds = Credentials.from_service_account_file(credentials_file, scopes=scope)
        client = gspread.authorize(creds)
        
        # Open the spreadsheet
        spreadsheet = client.open_by_key(spreadsheet_id)
        
        # Try to get the worksheet, create if it doesn't exist
        try:
            worksheet = spreadsheet.worksheet(sheet_name)
            # Clear existing data
            worksheet.clear()
        except gspread.exceptions.WorksheetNotFound:
            # Create new worksheet if it doesn't exist
            worksheet = spreadsheet.add_worksheet(title=sheet_name, rows=1000, cols=10)
        
        # Prepare data for writing - dynamically get headers from first item
        if not prs:
            return
        
        headers = list(prs[0].keys())
        data = [headers]
        
        for item in prs:
            row = [item.get(header, "") for header in headers]
            data.append(row)
        
        # Write data to the sheet
        worksheet.update('A1', data, value_input_option='RAW')
        
        # Format header row (bold) and auto-resize columns
        num_cols = len(headers)
        # Calculate column letter (A=1, B=2, ..., Z=26, AA=27, etc.)
        def get_column_letter(n):
            result = ""
            while n > 0:
                n -= 1
                result = chr(65 + (n % 26)) + result
                n //= 26
            return result
        
        header_range = f'A1:{get_column_letter(num_cols)}1'
        worksheet.format(header_range, {'textFormat': {'bold': True}})
        worksheet.columns_auto_resize(0, num_cols - 1)
        
        # Note: Google Sheets automatically makes URLs clickable, so no need for HYPERLINK formula
        
        print(f"\n✅ Exported {len(prs)} items to Google Sheets (tab: '{sheet_name}')\n")
        
    except FileNotFoundError:
        print(f"\n❌ Error: Credentials file '{credentials_file}' not found.")
        print("   Please download your Google service account credentials JSON file and save it as 'credentials.json'\n")
    except gspread.exceptions.SpreadsheetNotFound:
        print(f"\n❌ Error: Spreadsheet not found.")
        print(f"   Check that the spreadsheet ID is correct: {spreadsheet_id}")
        print("   Make sure you've shared the Google Sheet with your service account email.\n")
    except gspread.exceptions.APIError as e:
        if "PERMISSION_DENIED" in str(e) or "insufficient permissions" in str(e).lower():
            print(f"\n❌ Error: Permission denied.")
            print("   The service account doesn't have access to the spreadsheet.")
            print("   Please share the Google Sheet with the service account email (from credentials.json)")
            print("   and give it 'Editor' permissions.\n")
        elif "not enabled" in str(e).lower() or "API" in str(e):
            print(f"\n❌ Error: Google Sheets API not enabled.")
            print("   Please enable Google Sheets API and Google Drive API in Google Cloud Console.\n")
        else:
            print(f"\n❌ Error exporting to Google Sheets: {str(e)}\n")
    except Exception as e:
        error_msg = str(e)
        if "credentials" in error_msg.lower() or "authentication" in error_msg.lower():
            print(f"\n❌ Error: Authentication failed.")
            print("   Check that your credentials.json file is valid and not corrupted.\n")
        else:
            print(f"\n❌ Error exporting to Google Sheets: {str(e)}\n")

# === MAIN LOGIC ===
# Get members from all organizations (combine into one set)
all_org_members = set()
for org in ORG_NAMES:
    print(f"Fetching members from {org}...")
    org_members = get_org_members(org)
    all_org_members.update(org_members)
    print(f"  Found {len(org_members)} members")

# Collect PRs from all organizations
all_dependabot_prs = []
all_other_prs = []
all_external_prs = []

for org in ORG_NAMES:
    print(f"\nFetching repos and PRs from {org}...")
    repos = get_repos(org)
    print(f"  Found {len(repos)} repositories")
    dependabot_prs, other_prs, external_prs = get_stale_external_prs(org, repos, all_org_members, DAYS_THRESHOLD)
    all_dependabot_prs.extend(dependabot_prs)
    all_other_prs.extend(other_prs)
    all_external_prs.extend(external_prs)
    print(f"  Found {len(dependabot_prs)} dependabot/GitHub Actions PRs, {len(other_prs)} stale PRs (org + external), and {len(external_prs)} total external PRs")

print(f"\n🤖 Dependabot & GitHub Actions PRs (all open): {len(all_dependabot_prs)}\n")
if all_dependabot_prs:
    for pr in all_dependabot_prs:
        print(f"[{pr['org']}/{pr['repo']}] {pr['title']} – {pr['created_at']}")
        print(f"→ {pr['url']}\n")
else:
    print("No dependabot or GitHub Actions PRs found.\n")

print(f"\n👤 Stale PRs (> {DAYS_THRESHOLD} days): {len(all_other_prs)}\n")
if all_other_prs:
    for pr in all_other_prs:
        print(f"[{pr['org']}/{pr['repo']}] {pr['title']} by {pr['author']} – {pr['created_at']}")
        print(f"→ {pr['url']}\n")
else:
    print("No stale external PRs found.\n")

print(f"\n👥 All External PRs (all open): {len(all_external_prs)}\n")
if all_external_prs:
    print(f"Total of {len(all_external_prs)} external contributor PRs found (exported to '{EXTERNAL_PRS_TAB_NAME}' tab)\n")
else:
    print("No external PRs found.\n")

# Export to Google Sheets - separate tabs for dependabot and other PRs
# Prepare dependabot PRs data (with Severity column)
dependabot_prs_data = []
for pr in all_dependabot_prs:
    dependabot_prs_data.append({
        "Organization": pr["org"],
        "Repository": pr["repo"],
        "Title": pr["title"],
        "Author": pr["author"],  # Keep actual author (dependabot[bot] or github-actions[bot])
        "Severity": pr.get("severity", "N/A"),
        "Created At (UTC)": pr["created_at"],
        "URL": pr["url"]
    })

# Prepare stale PRs data (with Type column - Org Member or External)
other_prs_data = []
for pr in all_other_prs:
    # Determine if author is org member or external
    pr_type = "External" if is_external(pr["author"], all_org_members) else "Org Member"
    other_prs_data.append({
        "Organization": pr["org"],
        "Type": pr_type,
        "Repository": pr["repo"],
        "Title": pr["title"],
        "Author": pr["author"],
        "Created At (UTC)": pr["created_at"],
        "URL": pr["url"]
    })

# Prepare all external PRs data (without Type column)
all_external_prs_data = []
for pr in all_external_prs:
    all_external_prs_data.append({
        "Organization": pr["org"],
        "Repository": pr["repo"],
        "Title": pr["title"],
        "Author": pr["author"],
        "Created At (UTC)": pr["created_at"],
        "URL": pr["url"]
    })

# Get repos missing licenses
print(f"\n📋 Checking for repositories missing licenses...")
repos_missing_license = get_repos_missing_licenses(ORG_NAMES)
print(f"\n📋 Found {len(repos_missing_license)} repositories without licenses\n")

# Export to separate tabs
export_prs_to_tab(dependabot_prs_data, GOOGLE_SHEETS_ID, DEPENDABOT_TAB_NAME, GOOGLE_CREDENTIALS_FILE, include_type_column=False)
export_prs_to_tab(other_prs_data, GOOGLE_SHEETS_ID, GOOGLE_SHEETS_TAB_NAME, GOOGLE_CREDENTIALS_FILE, include_type_column=True)
export_prs_to_tab(all_external_prs_data, GOOGLE_SHEETS_ID, EXTERNAL_PRS_TAB_NAME, GOOGLE_CREDENTIALS_FILE, include_type_column=False)

# Export repos missing licenses
if repos_missing_license:
    export_prs_to_tab(repos_missing_license, GOOGLE_SHEETS_ID, MISSING_LICENSE_TAB_NAME, GOOGLE_CREDENTIALS_FILE, include_type_column=False)
else:
    print(f"\n✅ No repositories missing licenses found.\n")
