# [Flood] GitHub Repository Security Scanner

> **⚠️ Important Change (June 2026):** This tool has been updated to use a remotely maintained compromised packages list instead of locally created malware database JSON files. The scanner now downloads the latest [compromised-packages.txt](https://github.com/Cobenian/shai-hulud-detect/blob/main/compromised-packages.txt) from the Cobenian/shai-hulud-detect repository on each run. This means the tool's effectiveness now relies on that remote file being kept up to date as new attacks are discovered. If the remote source becomes stale or unavailable, the scanner will not detect newly compromised packages.

A Node.js tool that scans GitHub repositories for compromised npm dependencies across all branches. It checks `package.json` and `package-lock.json` files against a remotely maintained list of known compromised packages.

## What This Tool Does

This scanner checks multiple GitHub repositories and their branches for compromised dependencies. It downloads the latest [compromised-packages.txt](https://github.com/Cobenian/shai-hulud-detect/blob/main/compromised-packages.txt) file maintained by the community, which contains 3,290+ confirmed compromised package versions from multiple supply chain attacks between September 2025 and June 2026.

Attack campaigns covered include (but are not limited to):
- **Chalk/Debug Crypto Theft** *(September 2025)*
- **Sandworm Mode AI Toolchain Poisoning** *(February 2026)*
- **Axios Supply Chain Attack** *(March 2026)*
- **Mini Shai-Hulud / TanStack** *(May 2026)*
- **Mini Shai-Hulud AntV/atool wave** *(May 2026)*
- **Megalodon GitHub-repo backdooring** *(May 2026)*
- **Miasma @redhat-cloud-services** *(June 2026)*
- **Miasma Phantom Gyp** *(June 2026)*
- **IronWorm** *(June 2026)*
- And many more...

The list is continuously updated as new attacks are discovered.

The tool will:
- ✅ Download the latest compromised packages list remotely on each run
- ✅ Scan all configured repositories and their branches
- ✅ Check both `package.json` and `package-lock.json` files
- ✅ Identify if compromised versions are present
- ✅ Distinguish between safe and compromised versions of flagged packages
- ✅ Generate detailed reports itemised by attack campaign name and date

## Prerequisites

- **Node.js** 14.x or higher
- **GitHub Personal Access Token** with read-only access

## Installation & Setup

### Step 1: Install Dependencies

```bash
npm install --ignore-scripts
```

> ⚠️ **Security Note**: The `--ignore-scripts` flag prevents any postinstall scripts from running during installation, which is a security best practice when installing dependencies.

### Step 2: Configure GitHub Token

You have two options:

**Option A: Environment Variable (Recommended for CLI)**
```bash
export GITHUB_TOKEN=your_github_token_here
```

**Option B: .env File**
```bash
# Create .env file from template
cp .env.example .env

# Edit .env and add your token
nano .env
```

Add this line to `.env`:
```
GITHUB_TOKEN=your_github_token_here
```

### Step 3: Create a Read-Only GitHub Token

For security, create a token with **read-only** permissions:

1. Go to https://github.com/settings/tokens?type=beta (Fine-grained tokens)
2. Click **"Generate new token"**
3. Configure:
   - **Token name**: `repo-scanner-readonly`
   - **Expiration**: 90 days (recommended)
   - **Repository access**: Select "Only select repositories"
   - **Resource owner**: Select DEFRA for DEFRA repositories
   - Choose the defra repositories you need to scan
4. **Repository permissions**:
   - **Contents**: `Read-only` ✅
   - **Metadata**: `Read-only` ✅
   - All others: `No access`
5. Generate and copy the token

This ensures the token can **only read** files and cannot modify anything.

## Configuration

The scanner is pre-configured to check these repositories:

- `defra/flood-app`
- `defra/flood-service`
- `defra/flood-db`
- `defra/flood-gis`
- `defra/flood-webchat`
- `defra/cap-xml`
- `defra/cap-xml-db`
- `defra/fws-app`
- `defra/fws-api`
- `defra/fws-db`
- `defra/flood-data`
- `defra/flood-service-tests-v2`
- `defra/cap-xml-tests`
- `defra/cyltfr-app`
- `defra/cyltfr-service`
- `defra/cyltfr-admin`
- `defra/cyltfr-data`
- `defra/fmp-app`
- `defra/fmp-service`
- `defra/fmp-api`
- `defra/fmp-riskadmin-api`
- `defra/fmp-gis-gp-services`

Please comment out any repositories that you're not interested in scanning.

```javascript
repositories: [
  { owner: 'defra', repo: 'flood-app' },
  { owner: 'your-org', repo: 'your-repo' },
  // Add more repositories here
],
```

### Other Settings

- `maxBranchesPerRepo`: Set to `0` to scan all branches, or specify a number to limit
- `targetFiles`: Files to check (default: `package.json`, `package-lock.json`)

## Usage

Run the scanner:

```bash
npm start
```

The scanner will:
1. Download the latest compromised packages list from the remote source
2. Display how many attack campaigns and packages were loaded
3. Check your GitHub API rate limit
4. Scan each repository's branches
5. Check for all compromised packages
6. Display real-time results in the console
7. Save detailed JSON and summary text reports

## Understanding the Output

### Startup Output

When the scanner starts, you'll see the compromised packages list being downloaded:

```
Downloading compromised packages list from remote source...
  URL: https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt
  ✓ Downloaded and parsed successfully
  ✓ Found 15 attack campaign(s)
  ✓ Total: 1724 unique compromised npm package(s)

GitHub Repository Security Scanner
==================================

API Rate Limit: 4998/5000 remaining
Resets at: Mon Jun 09 2026 12:00:00 GMT+0000
```

### Console Output

The scanner provides real-time output showing:

- Remote compromised packages list download status
- API rate limit status
- Repository and branch being scanned
- Status of each file (SAFE or COMPROMISED)
- Details of any compromised packages found
- Warnings for packages that are flagged but using safe versions
- Final summary report

Example output:

```
GitHub Repository Security Scanner
==================================

API Rate Limit: 4998/5000 remaining
Resets at: Mon Mar 31 2026 12:00:00 GMT+0000

================================================================================
Scanning repository: defra/flood-app
================================================================================
Found 15 branch(es)

  Branch: main
    ✓ Overall Status: SAFE
      ✓ package.json: SAFE
      ✓ package-lock.json: SAFE

  Branch: feature/update-deps
    ✗ Overall Status: COMPROMISED
      ✗ package.json: COMPROMISED
        🔴 axios@1.14.1 - CRITICAL
           Compromised package detected on March 31, 2026
      ✗ package-lock.json: COMPROMISED
        🔴 axios@1.14.1 - CRITICAL
           Compromised package detected on March 31, 2026

  Branch: develop
    ✓ Overall Status: SAFE
      ✓ package.json: SAFE
        🟡 axios@1.6.0 - Package present but version is safe
           Compromised versions: 1.14.1, 0.30.4
```

### Status Indicators

- ✓ **SAFE**: No compromised packages found
- ✗ **COMPROMISED**: One or more compromised packages detected
- 🔴 **Compromised Package**: Package using a known compromised version
- 🟡 **Warning**: Package is in malware DB but using a safe version
- ⊘ **Not found**: File doesn't exist in this branch

## Generated Reports

The scanner automatically generates **two reports** after each scan:

### 1. Summary Report (For Management)

**File**: `summary-2026-03-31T10-30-45-123Z.txt`

A concise, human-readable text report perfect for sharing with management. Includes:

- **Overall Summary**: Total repositories, branches, issues found, and status
- **Per-Repository Table**: Quick overview showing branches scanned and issues per repo
- **Compromised Packages Details**: Only shows issues that need attention (no noise from safe packages)
- **Recommendations**: Actionable next steps

Example summary report excerpt:

```
================================================================================
                    SECURITY SCAN SUMMARY REPORT
================================================================================

Scan Date: 2026-03-31T10:30:45.123Z
Scanner Version: 1.0.0

================================================================================
OVERALL SUMMARY
================================================================================

Total Repositories Scanned: 11
Total Branches Scanned:     142
Safe Branches:              138
Compromised Branches:       4
Total Issues Found:         5

Status: ❌ VULNERABILITIES DETECTED

================================================================================
PER-REPOSITORY SUMMARY
================================================================================

Repository                  Branches  Issues  Status
────────────────────────────────────────────────────────────────────────────────
defra/flood-app                   15       2  ❌ COMPROMISED
defra/flood-service               12       0  ✅ SAFE
defra/flood-db                     8       0  ✅ SAFE
defra/flood-gis                   10       0  ✅ SAFE
defra/flood-webchat                5       1  ❌ COMPROMISED
defra/cap-xml                      6       0  ✅ SAFE

================================================================================
COMPROMISED PACKAGES DETAILS
================================================================================

defra/flood-app
────────────────────────────────────────────────────────────────────────────────
  1. axios@1.14.1 (CRITICAL)
     Branch: feature/update-deps
     File: package.json
     Description: Compromised package detected on March 31, 2026
```

**Key Features:**
- ✅ Compact table format for easy scanning
- ✅ Only shows compromised package details (no clutter from safe packages)
- ✅ Clear statistics per repository
- ✅ Perfect for executive summaries and management reports

### 2. Detailed JSON Report (For Technical Analysis)

**File**: `report-2026-03-31T10-30-45-123Z.json`

A comprehensive JSON file with complete technical details:

- **Summary statistics**: Total repos, branches, safe/compromised counts
- **Complete results**: Every repository and branch scanned
- **All findings**: Compromised packages and warnings
- **File-level details**: Specific file results and dependency trees

Use this report for:
- Automated processing and integration
- Detailed technical analysis
- Archiving and audit trails
- Feeding into other security tools

### Accessing the Reports

After the scan completes, you'll see:

```
✓ Detailed JSON report saved to: ./report-2026-03-31T10-30-45-123Z.json
✓ Summary report saved to: ./summary-2026-03-31T10-30-45-123Z.txt

📄 Share the summary report with management for easy reading.
```

**For management presentations**: Use the `summary-*.txt` file  
**For technical deep-dive**: Use the `report-*.json` file

### Final Summary

After scanning, you'll see a summary like this:

```
================================================================================
FINAL REPORT
================================================================================

Summary:
  Total Repositories Scanned: 11
  Total Branches Scanned: 142
  Safe Branches: 138
  Compromised Branches: 4

Detailed Results:

✗ COMPROMISED | defra/flood-app | Branch: feature/update-deps
        └─ axios@1.14.1 in package.json
        └─ axios@1.14.1 in package-lock.json
✓ SAFE | defra/flood-app | Branch: main
        ℹ  axios@1.6.0 (safe version) in package.json
✓ SAFE | defra/flood-service | Branch: main
✓ SAFE | defra/flood-db | Branch: main
...
```

## Presenting Results to Management

**📄 Use the Summary Report**: The `summary-*.txt` file is specifically designed for management presentations. It provides:

### What's Included in the Summary Report

1. **Overall Status**: How many repositories/branches are affected at a glance
2. **Per-Repository Breakdown**: Individual status for each repository with branch counts
3. **Compromised Branches**: Complete list of all affected branches with specific issues
4. **Exact Package Details**: Package names, versions, and severity levels
5. **Safe Version Warnings**: Repositories using flagged packages but with safe versions
6. **Actionable Recommendations**: Clear next steps based on findings

### Key Information in Your Report

The summary automatically includes:

- **Package Name**: axios (or other compromised packages)
- **Compromised Versions**: 1.14.1, 0.30.4
- **Detection Date**: Timestamp of scan
- **Severity**: CRITICAL
- **Files Checked**: package.json and package-lock.json
- **Branches Scanned**: All branches for each repository
- **Immediate Actions**: Recommendations for remediation

### How to Share

Simply email or share the `summary-*.txt` file - it's formatted for easy reading without technical JSON knowledge. The summary report is self-contained and requires no additional explanation.

## Exit Codes

The scanner exits with specific codes:

- `0`: ✅ All scanned branches are safe
- `1`: ❌ One or more compromised branches found (or error occurred)

This allows the scanner to be used in CI/CD pipelines or automated security checks.

## Compromised Packages Database

The scanner automatically downloads the latest compromised packages list from:

**https://github.com/Cobenian/shai-hulud-detect/blob/main/compromised-packages.txt**

This community-maintained file contains 3,290+ confirmed compromised package versions from multiple supply chain attacks. It is updated regularly as new attacks are discovered, so no manual database maintenance is required.

### How It Works

1. On each run, the scanner downloads the latest `compromised-packages.txt` file
2. The file is parsed into attack campaigns (grouped by date and attack name)
3. Each npm package entry is extracted with its compromised version(s)
4. Reports are itemised by attack campaign for clear context

### Configuring the Source URL

The remote URL is configured in `config.js`:

```javascript
compromisedPackagesUrl: 'https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt',
```

You can change this to point to a different source or a local mirror if needed.

### Sources

The compromised packages list aggregates data from:
- [StepSecurity](https://www.stepsecurity.io)
- [Wiz.io](https://www.wiz.io)
- [Semgrep](https://semgrep.dev)
- [JFrog Security](https://jfrog.com/blog)
- [Socket.dev](https://socket.dev)

## API Rate Limiting

GitHub API limits:
- **Authenticated**: 5,000 requests/hour
- **Unauthenticated**: 60 requests/hour

The scanner displays your rate limit status at startup. If you exceed the limit:
- Wait for the reset time (shown in output)
- Use `maxBranchesPerRepo` in config.js to limit branches per repo
- Scan fewer repositories at once

## Troubleshooting

### Error: "GITHUB_TOKEN not set"
**Solution:**
- Ensure you've set the environment variable: `export GITHUB_TOKEN=your_token`
- Or create a `.env` file with `GITHUB_TOKEN=your_token`
- Verify the token is valid and not expired

### Warning: "No branches found"
**Possible causes:**
- Repository doesn't exist or is misspelled in config.js
- Your token doesn't have access to the repository
- Repository is private and token lacks permissions

### Error: "Rate limit exceeded"
**Solution:**
- Wait for the rate limit reset (time shown in error)
- Reduce the number of repositories being scanned
- Set `maxBranchesPerRepo: 10` in config.js to limit branches

### File not found (404 errors)
**This is normal:**
- Some branches may not have package.json or package-lock.json
- Not all repositories are Node.js projects
- The scanner will continue and report missing files

### Dependencies installation fails
**Solution:**
- Ensure Node.js 14.x or higher is installed
- Run with `npm ci --ignore-scripts` to skip postinstall scripts
- Check your internet connection

## Project Structure

```
repo-scanner/
├── index.js                          # Main entry point
├── scanner.js                        # Core scanning logic
├── github-api.js                     # GitHub API client
├── dependency-checker.js             # Dependency analysis
├── compromised-packages-loader.js    # Remote compromised packages downloader/parser
├── config.js                         # Repository configuration
├── package.json                      # npm dependencies
├── .env.example                      # Environment variable template
├── .env                              # Your GitHub token (create this, never commit)
├── .gitignore                        # Prevents committing sensitive files
└── README.md                         # This file
```

## Security Best Practices

✅ **Do:**
- Always use `npm install --ignore-scripts` to prevent malicious postinstall scripts
- Use read-only GitHub tokens (Contents: Read-only)
- Set token expiration dates (90 days recommended)
- Keep `.env` file out of version control (already in .gitignore)
- Review the JSON reports and share findings with your security team
- Review flagged packages but marked as safe, to ensure that they don't pose a higher risk due to the number of incidents in the past

❌ **Don't:**
- Commit GitHub tokens to repositories
- Use tokens with write permissions for read-only tasks
- Share tokens or commit `.env` files
- Set "No expiration" on tokens unless absolutely necessary
- Ignore warnings about packages that are flagged but using safe versions

## Development

### Code Style

This project uses [StandardJS](https://standardjs.com) for code linting and formatting.

**Available commands:**

```bash
# Check code style
npm run lint

# Automatically fix code style issues
npm run lint:fix
```

**StandardJS Rules:**
- No semicolons
- 2 spaces for indentation
- Single quotes for strings
- Space after function name
- Always use `===` instead of `==`
- And more...

The linter runs automatically when you commit code (recommended to set up a pre-commit hook).

**Editor Integration:**

For a better development experience, install StandardJS extensions for your editor:
- VS Code: [JavaScript Standard Style](https://marketplace.visualstudio.com/items?itemName=standard.vscode-standard)
- Atom: [linter-js-standard](https://atom.io/packages/linter-js-standard)

### Testing

This project uses [Jest](https://jestjs.io) for unit testing.

**Available commands:**

```bash
# Run all tests
npm test
```

Tests are located in the `test/` directory and cover:
- `compromised-packages-loader.test.js` — Remote file parsing and section extraction
- `dependency-checker.test.js` — Version comparison and dependency analysis
- `scanner.test.js` — Full scan flow with mocked GitHub API
- `github-api.test.js` — Git Trees API file discovery and content retrieval
- Sublime Text: [SublimeLinter-contrib-standard](https://packagecontrol.io/packages/SublimeLinter-contrib-standard)

## Support

For questions or issues:
- Check the Troubleshooting section above
- Review the JSON report for detailed findings
- Contact your security team with the generated reports

## License

ISC

