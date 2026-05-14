# GitHub Repository Security Scanner

A Node.js tool that scans GitHub repositories for compromised npm dependencies across all branches. It checks `package.json` and `package-lock.json` files against a database of known malware-compromised packages.

## What This Tool Does

This scanner checks multiple GitHub repositories and their branches for compromised dependencies. It currently scans for:
- **axios-compromise-2026** *(March 31, 2026)*: 1 package (axios) — [Source](https://safedep.io/axios-npm-supply-chain-compromise)
- **canister-worm** *(March 20, 2026)*: 62 packages (@emilgroup/* SDKs, @opengov/* packages, etc.) — [Source](https://socket.dev/blog/canisterworm-npm-publisher-compromise-deploys-backdoor-across-29-packages)
- **shai-hulud** *(September 8, 2025)*: 18 packages (chalk, ansi-styles, color utilities, etc.) — [Source](https://socket.dev/blog/npm-author-qix-compromised-in-major-supply-chain-attack)
- **singularity** *(September 14–16, 2025)*: 195 packages (@ctrl/*, @nativescript-community/*, @operato/*, Angular/Ember packages, etc.) — [Source](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
- **mini-shai-hulud** *(May 11, 2026)*: 175 packages (TanStack router ecosystem, UiPath, @squawk, @mistralai, OpenSearch, and others) — [Source](https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack)

The tool will:
- ✅ Scan all configured repositories and their branches
- ✅ Check both `package.json` and `package-lock.json` files
- ✅ Load multiple malware databases automatically
- ✅ Identify if compromised versions are present
- ✅ Distinguish between safe and compromised versions of flagged packages
- ✅ Generate detailed reports for management

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

To modify the repository list, edit `config.js`:

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
1. Load all malware databases from `malware-dbs/` directory
2. Display which databases were loaded and how many packages
3. Check your GitHub API rate limit
4. Scan each repository's branches
5. Check for all compromised packages across all databases
6. Display real-time results in the console
7. Save detailed JSON and summary text reports

## Understanding the Output

### Startup Output

When the scanner starts, you'll see the malware databases being loaded:

```
Loading malware databases from ./malware-dbs...
  ✓ Loaded axios-2026.json: 1 package(s) from axios-compromise-2026
  ✓ Loaded shai-hulud.json: 18 package(s) from shai-hulud
Total: 19 unique compromised package(s) from 2 database(s)

GitHub Repository Security Scanner
==================================

API Rate Limit: 4998/5000 remaining
Resets at: Mon Mar 31 2026 12:00:00 GMT+0000
```

### Console Output

The scanner provides real-time output showing:

- Malware databases loaded at startup
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

## Malware Database

### Multiple Database Support

The scanner loads malware definitions from the `malware-dbs/` directory. All `.json` files in this directory are automatically loaded at startup.

**Current databases:**
- `axios-2026.json` - axios compromise, March 31, 2026 (1 package) — [Source](https://safedep.io/axios-npm-supply-chain-compromise)
- `canister-worm.json` - CanisterWorm, March 20, 2026 (62 packages) — [Source](https://socket.dev/blog/canisterworm-npm-publisher-compromise-deploys-backdoor-across-29-packages)
- `shai-hulud.json` - Shai-Hulud worm (Qix- maintainer compromise), September 8, 2025 (18 packages) — [Source](https://socket.dev/blog/npm-author-qix-compromised-in-major-supply-chain-attack)
- `singularity.json` - Shai-Hulud worm (broader campaign), September 14–16, 2025 (195 packages) — [Source](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
- `mini-shai-hulud.json` - Mini Shai-Hulud / TeamPCP, May 11, 2026 (175 packages) — [Source](https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack)

When you run the scanner, you'll see:
```
Loading malware databases from ./malware-dbs...
  ✓ Loaded axios-2026.json: 1 package(s) from axios-compromise-2026
  ✓ Loaded canister-worm.json: 62 package(s) from canister-worm
  ✓ Loaded mini-shai-hulud.json: 175 package(s) from mini-shai-hulud
  ✓ Loaded shai-hulud.json: 18 package(s) from shai-hulud
  ✓ Loaded singularity.json: 195 package(s) from singularity
Total: 451 unique compromised package(s) from 5 database(s)
```

### Adding New Malware Databases

To add a new vulnerability database:

1. **Create a new JSON file** in the `malware-dbs/` directory (e.g., `canister-worm.json`)

2. **Use this format:**

```json
{
  "vulnerability": "vulnerability-name",
  "description": "Description of the vulnerability",
  "severity": "critical",
  "compromisedPackages": [
    {
      "name": "package-name",
      "compromisedVersions": ["1.0.0", "1.0.1"],
      "description": "Specific details about this package",
      "severity": "critical"
    }
  ]
}
```

3. **Restart the scanner** - it will automatically load the new file

**Tips:**
- Use `"*"` in `compromisedVersions` to flag all versions of a package
- Set severity to `critical`, `high`, `medium`, or `low`
- Each file can contain multiple packages
- See `malware-dbs/README.md` for detailed format documentation

**Sources for compromised packages:**
- https://github.com/advisories
- https://snyk.io/vuln/npm
- https://socket.dev/npm/
- npm security advisories

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
├── index.js                  # Main entry point
├── scanner.js                # Core scanning logic
├── github-api.js             # GitHub API client
├── dependency-checker.js     # Dependency analysis
├── config.js                 # Repository configuration
├── malware-dbs/              # Malware database directory
│   ├── README.md             # Database format documentation
│   ├── axios-2026.json       # axios compromise database
│   ├── canister-worm.json    # CanisterWorm database (March 20, 2026)
│   ├── mini-shai-hulud.json  # Mini Shai-Hulud / TeamPCP database
│   ├── shai-hulud.json       # Shai-Hulud worm database (Sep 8, 2025)
│   └── singularity.json      # Singularity / Shai-Hulud worm database (Sep 14-16, 2025)
├── package.json              # npm dependencies
├── .env.example              # Environment variable template
├── .env                      # Your GitHub token (create this, never commit)
├── .gitignore                # Prevents committing sensitive files
└── README.md                 # This file
```

## Security Best Practices

✅ **Do:**
- Always use `npm install --ignore-scripts` to prevent malicious postinstall scripts
- Use read-only GitHub tokens (Contents: Read-only)
- Set token expiration dates (90 days recommended)
- Keep `.env` file out of version control (already in .gitignore)
- Regularly update the malware database with new threats
- Review the JSON reports and share findings with your security team

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
- Sublime Text: [SublimeLinter-contrib-standard](https://packagecontrol.io/packages/SublimeLinter-contrib-standard)

## Support

For questions or issues:
- Check the Troubleshooting section above
- Review the JSON report for detailed findings
- Contact your security team with the generated reports

## License

ISC

