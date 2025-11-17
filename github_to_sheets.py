# File: github_to_sheets.py

import os
from datetime import datetime, timedelta
from github import Github
import gspread
from oauth2client.service_account import ServiceAccountCredentials

# --- Config ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
ORG_NAME = "viamrobotics"
GOOGLE_SHEET_NAME = "Viam GitHub Dashboard"
GOOGLE_CREDS_FILE = "google-credentials.json"  # Replace with your downloaded service account file

# --- Auth ---
g = Github(GITHUB_TOKEN)
org = g.get_organization(ORG_NAME)
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]
creds = ServiceAccountCredentials.from_json_keyfile_name(GOOGLE_CREDS_FILE, scope)
gs = gspread.authorize(creds)
sheet = gs.open(GOOGLE_SHEET_NAME)

# --- Utils ---
def write_to_sheet(tab, rows):
    ws = sheet.worksheet(tab)
    ws.clear()
    if rows:
        ws.append_rows(rows)

# --- PRs ---
def get_open_external_prs():
    print("Fetching open PRs...")
    data = [["Repo", "Title", "Author", "Created At", "URL"]]
    for repo in org.get_repos():
        for pr in repo.get_pulls(state='open'):
            if pr.user.type == "User" and not is_member(pr.user.login):
                data.append([repo.name, pr.title, pr.user.login, pr.created_at.isoformat(), pr.html_url])
    write_to_sheet("open_prs", data)

# --- External Issues ---
def get_external_issues():
    print("Fetching external issues...")
    data = [["Repo", "Title", "Author", "Created At", "URL"]]
    for repo in org.get_repos():
        for issue in repo.get_issues(state='open'):
            if not issue.pull_request and not is_member(issue.user.login):
                data.append([repo.name, issue.title, issue.user.login, issue.created_at.isoformat(), issue.html_url])
    write_to_sheet("external_issues", data)

# --- Dependabot Alerts ---
def get_dependabot_alerts():
    print("(Placeholder) Dependabot alerts require the GitHub Security API or GraphQL.")
    data = [["Repo", "Dependency", "Severity", "URL"]]
    # Add your logic with GitHub GraphQL API or REST once enabled
    write_to_sheet("dependabot_alerts", data)

# --- SDK Versions ---
def get_sdk_versions():
    print("Scanning SDK versions...")
    data = [["Repo", "File", "Line"]]
    keywords = ["viam-sdk", "@viamrobotics/sdk"]
    for repo in org.get_repos():
        try:
            for file in ["requirements.txt", "package.json"]:
                contents = repo.get_contents(file)
                lines = contents.decoded_content.decode().splitlines()
                for line in lines:
                    if any(keyword in line for keyword in keywords):
                        data.append([repo.name, file, line.strip()])
        except Exception:
            continue
    write_to_sheet("sdk_versions", data)

# --- Helpers ---
def is_member(username):
    try:
        org.get_member(username)
        return True
    except:
        return False

# --- Main ---
if __name__ == "__main__":
    get_open_external_prs()
    get_external_issues()
    get_dependabot_alerts()
    get_sdk_versions()
    print("✅ Data synced to Google Sheets!")
