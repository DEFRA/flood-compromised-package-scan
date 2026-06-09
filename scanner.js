const GitHubAPI = require('./github-api')
const DependencyChecker = require('./dependency-checker')
const CompromisedPackagesLoader = require('./compromised-packages-loader')

class Scanner {
  constructor (config) {
    this.config = config
    this.githubApi = new GitHubAPI(config.githubToken)
    this.checker = new DependencyChecker()
    this.loader = new CompromisedPackagesLoader(config.compromisedPackagesUrl)
    this.results = []
  }

  /**
   * Scan a single repository across all branches
   */
  async scanRepository (owner, repo) {
    console.log(`\n${'='.repeat(80)}`)
    console.log(`Scanning repository: ${owner}/${repo}`)
    console.log('='.repeat(80))

    try {
      // Get all branches
      const branches = await this.githubApi.getBranches(owner, repo)

      if (branches.length === 0) {
        console.log(`No branches found for ${owner}/${repo}`)
        return
      }

      console.log(`Found ${branches.length} branch(es)`)

      // Limit branches if configured
      const branchesToScan = this.config.maxBranchesPerRepo > 0
        ? branches.slice(0, this.config.maxBranchesPerRepo)
        : branches

      // Scan each branch
      for (const branch of branchesToScan) {
        await this.scanBranch(owner, repo, branch)
      }
    } catch (error) {
      console.error(`Error scanning repository ${owner}/${repo}:`, error.message)
    }
  }

  /**
   * Scan a single branch for compromised dependencies
   */
  async scanBranch (owner, repo, branch) {
    console.log(`\n  Branch: ${branch}`)

    const branchResult = {
      owner,
      repo,
      branch,
      files: [],
      overallStatus: 'SAFE',
      compromisedFiles: 0,
      safeFiles: 0,
      missingFiles: 0
    }

    // Find all matching files in the repository tree
    const matchingPaths = await this.githubApi.findFiles(owner, repo, branch, this.config.targetFiles)

    if (matchingPaths.length === 0) {
      console.log('    ⊘ No package.json or package-lock.json files found')
      branchResult.missingFiles++
      this.results.push(branchResult)
      this.printBranchSummary(branchResult)
      return
    }

    // Scan each discovered file
    for (const filePath of matchingPaths) {
      const fileResult = await this.scanFile(owner, repo, branch, filePath)

      if (fileResult) {
        branchResult.files.push(fileResult)

        if (fileResult.status === 'COMPROMISED') {
          branchResult.compromisedFiles++
          branchResult.overallStatus = 'COMPROMISED'
        } else if (fileResult.status === 'SAFE') {
          branchResult.safeFiles++
        }
      }
    }

    this.results.push(branchResult)
    this.printBranchSummary(branchResult)
  }

  /**
   * Scan a single file in a branch
   */
  async scanFile (owner, repo, branch, filePath) {
    const content = await this.githubApi.getFileContent(owner, repo, filePath, branch)

    if (!content) {
      console.log(`    ⊘ ${filePath}: Not found`)
      return null
    }

    const filename = filePath.split('/').pop()
    const analysis = this.checker.analyzeDependencies(content, filename)
    const report = this.checker.generateFileReport(analysis, filePath)

    return report
  }

  /**
   * Print summary for a branch
   */
  printBranchSummary (branchResult) {
    const statusSymbol = branchResult.overallStatus === 'SAFE' ? '✓' : '✗'

    console.log(`    ${statusSymbol} Overall Status: ${branchResult.overallStatus}`)

    branchResult.files.forEach(fileResult => {
      const fileSymbol = fileResult.status === 'SAFE' ? '✓' : '✗'
      console.log(`      ${fileSymbol} ${fileResult.filename}: ${fileResult.status}`)

      if (fileResult.compromisedCount > 0) {
        fileResult.details.compromised.forEach(c => {
          console.log(`        🔴 ${c.package}@${c.version} - ${c.severity.toUpperCase()}`)
          console.log(`           ${c.description}`)
        })
      }

      if (fileResult.packagePresentCount > 0) {
        fileResult.details.packagePresent.forEach(p => {
          console.log(`        🟡 ${p.package}@${p.version} - ${p.status}`)
          console.log(`           Compromised versions: ${p.compromisedVersions.join(', ')}`)
        })
      }
    })
  }

  /**
   * Generate final report
   */
  generateReport () {
    console.log(`\n${'='.repeat(80)}`)
    console.log('FINAL REPORT')
    console.log('='.repeat(80))

    const summary = {
      totalRepositories: new Set(this.results.map(r => `${r.owner}/${r.repo}`)).size,
      totalBranches: this.results.length,
      safeBranches: this.results.filter(r => r.overallStatus === 'SAFE').length,
      compromisedBranches: this.results.filter(r => r.overallStatus === 'COMPROMISED').length
    }

    console.log('\nSummary:')
    console.log(`  Total Repositories Scanned: ${summary.totalRepositories}`)
    console.log(`  Total Branches Scanned: ${summary.totalBranches}`)
    console.log(`  Safe Branches: ${summary.safeBranches}`)
    console.log(`  Compromised Branches: ${summary.compromisedBranches}`)

    console.log('\nDetailed Results:\n')

    this.results.forEach(result => {
      const status = result.overallStatus === 'SAFE' ? '✓ SAFE' : '✗ COMPROMISED'
      console.log(`${status} | ${result.owner}/${result.repo} | Branch: ${result.branch}`)

      if (result.overallStatus === 'COMPROMISED') {
        result.files.forEach(file => {
          if (file.status === 'COMPROMISED') {
            file.details.compromised.forEach(c => {
              console.log(`        └─ ${c.package}@${c.version} in ${file.filename}`)
            })
          }
        })
      }

      // Show packages present but safe
      result.files.forEach(file => {
        if (file.packagePresentCount > 0) {
          file.details.packagePresent.forEach(p => {
            console.log(`        ℹ  ${p.package}@${p.version} (safe version) in ${file.filename}`)
          })
        }
      })
    })

    return {
      summary,
      results: this.results
    }
  }

  /**
   * Generate a summary report in readable text format
   */
  generateSummaryReport () {
    const timestamp = new Date().toISOString()
    let report = ''

    // Header
    report += '================================================================================\n'
    report += '                    SECURITY SCAN SUMMARY REPORT\n'
    report += '================================================================================\n\n'
    report += `Scan Date: ${timestamp}\n`
    report += 'Scanner Version: 1.0.0\n\n'

    // Overall Summary
    const totalRepos = new Set(this.results.map(r => `${r.owner}/${r.repo}`)).size
    const totalBranches = this.results.length
    const safeBranches = this.results.filter(r => r.overallStatus === 'SAFE').length
    const compromisedBranches = this.results.filter(r => r.overallStatus === 'COMPROMISED').length

    // Count total packages scanned and issues
    let totalIssues = 0
    this.results.forEach(result => {
      result.files.forEach(file => {
        if (file.details && file.details.compromised) {
          totalIssues += file.details.compromised.length
        }
      })
    })

    report += '================================================================================\n'
    report += 'OVERALL SUMMARY\n'
    report += '================================================================================\n\n'
    report += `Total Repositories Scanned: ${totalRepos}\n`
    report += `Total Branches Scanned:     ${totalBranches}\n`
    report += `Safe Branches:              ${safeBranches}\n`
    report += `Compromised Branches:       ${compromisedBranches}\n`
    report += `Total Issues Found:         ${totalIssues}\n`
    report += `\nStatus: ${compromisedBranches > 0 ? '❌ VULNERABILITIES DETECTED' : '✅ ALL CLEAR'}\n\n`

    // Vulnerabilities Scanned Section
    const vulnStats = this.checker.getVulnerabilityStats()
    if (vulnStats && vulnStats.length > 0) {
      report += '================================================================================\n'
      report += 'VULNERABILITIES SCANNED\n'
      report += '================================================================================\n\n'

      const totalPackages = vulnStats.reduce((sum, v) => sum + v.packageCount, 0)
      report += `Total Vulnerability Databases: ${vulnStats.length}\n`
      report += `Total Packages in Database:    ${totalPackages}\n\n`

      vulnStats.forEach(vuln => {
        report += `• ${vuln.name}\n`
        report += `  Packages: ${vuln.packageCount}\n`
        if (vuln.description) {
          report += `  Description: ${vuln.description}\n`
        }
        report += '\n'
      })
    }

    // Per-Repository Summary Table
    report += '================================================================================\n'
    report += 'PER-REPOSITORY SUMMARY\n'
    report += '================================================================================\n\n'

    // Group results by repository
    const repoGroups = new Map()
    this.results.forEach(result => {
      const repoKey = `${result.owner}/${result.repo}`
      if (!repoGroups.has(repoKey)) {
        repoGroups.set(repoKey, [])
      }
      repoGroups.get(repoKey).push(result)
    })

    // Table header
    report += 'Repository                  Branches  Issues  Status\n'
    report += '─'.repeat(80) + '\n'

    // Generate summary for each repository
    const repoStats = []
    repoGroups.forEach((branches, repoName) => {
      const compromisedBranchCount = branches.filter(b => b.overallStatus === 'COMPROMISED').length
      const totalBranchCount = branches.length

      // Count issues in this repo
      let issuesCount = 0
      branches.forEach(branch => {
        branch.files.forEach(file => {
          if (file.details && file.details.compromised) {
            issuesCount += file.details.compromised.length
          }
        })
      })

      const status = compromisedBranchCount > 0 ? '❌ COMPROMISED' : '✅ SAFE'
      const padding = ' '.repeat(Math.max(0, 28 - repoName.length))

      report += `${repoName}${padding}${totalBranchCount.toString().padStart(8)}  ${issuesCount.toString().padStart(6)}  ${status}\n`

      repoStats.push({
        repoName,
        branches,
        totalBranchCount,
        compromisedBranchCount,
        issuesCount
      })
    })

    report += '\n'

    // Detailed Issues Section - Only if there are compromised packages
    const allCompromised = []
    this.results.forEach(result => {
      result.files.forEach(file => {
        if (file.details && file.details.compromised) {
          file.details.compromised.forEach(c => {
            allCompromised.push({
              repo: `${result.owner}/${result.repo}`,
              branch: result.branch,
              package: c.package,
              version: c.version,
              severity: c.severity,
              description: c.description,
              file: file.filename
            })
          })
        }
      })
    })

    if (allCompromised.length > 0) {
      report += '================================================================================\n'
      report += 'COMPROMISED PACKAGES DETAILS\n'
      report += '================================================================================\n\n'

      // Group by repository
      const issuesByRepo = new Map()
      allCompromised.forEach(item => {
        if (!issuesByRepo.has(item.repo)) {
          issuesByRepo.set(item.repo, [])
        }
        issuesByRepo.get(item.repo).push(item)
      })

      issuesByRepo.forEach((issues, repoName) => {
        report += `${repoName}\n`
        report += '─'.repeat(80) + '\n'

        issues.forEach((item, index) => {
          report += `  ${index + 1}. ${item.package}@${item.version} (${item.severity.toUpperCase()})\n`
          report += `     Branch: ${item.branch}\n`
          report += `     File: ${item.file}\n`
          report += `     Description: ${item.description}\n\n`
        })
      })
    }

    // Recommendations
    report += '================================================================================\n'
    report += 'RECOMMENDATIONS\n'
    report += '================================================================================\n\n'

    if (compromisedBranches > 0) {
      report += '⚠️  IMMEDIATE ACTION REQUIRED:\n\n'
      report += '1. Review all compromised packages listed above\n'
      report += '2. Update or remove compromised packages immediately\n'
      report += '3. Verify no malicious code has been executed\n'
      report += '4. Run security audits on affected systems\n\n'
    } else {
      report += '✅ No compromised packages detected.\n\n'
      report += 'Continue monitoring for new vulnerabilities and keep dependencies updated.\n\n'
    }

    // Footer
    report += '================================================================================\n'
    report += `Report generated: ${timestamp}\n`
    report += 'For detailed technical information, see the accompanying JSON report.\n'
    report += '================================================================================\n'

    return report
  }

  /**
   * Run the scanner on all configured repositories
   */
  async run () {
    console.log('GitHub Repository Security Scanner')
    console.log('==================================\n')

    // Download and load the compromised packages list
    const remoteData = await this.loader.load()
    this.checker.loadFromRemoteData(remoteData)

    // Check rate limit
    const rateLimit = await this.githubApi.checkRateLimit()
    if (rateLimit) {
      console.log(`API Rate Limit: ${rateLimit.remaining}/${rateLimit.limit} remaining`)
      console.log(`Resets at: ${rateLimit.reset}\n`)
    }

    // Scan each repository
    for (const repoConfig of this.config.repositories) {
      await this.scanRepository(repoConfig.owner, repoConfig.repo)
    }

    // Generate final report
    return this.generateReport()
  }
}

module.exports = Scanner
