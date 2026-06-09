const https = require('https')

const COMPROMISED_PACKAGES_URL = 'https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt'

class CompromisedPackagesLoader {
  constructor (url) {
    this.url = url || COMPROMISED_PACKAGES_URL
  }

  /**
   * Download the compromised packages text file from the remote URL
   */
  async download () {
    return new Promise((resolve, reject) => {
      const request = (url) => {
        https.get(url, (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            request(res.headers.location)
            return
          }

          if (res.statusCode !== 200) {
            reject(new Error(`Failed to download compromised packages list: HTTP ${res.statusCode}`))
            return
          }

          let data = ''
          res.on('data', (chunk) => { data += chunk })
          res.on('end', () => resolve(data))
          res.on('error', reject)
        }).on('error', reject)
      }

      request(this.url)
    })
  }

  /**
   * Parse the compromised packages text file into structured data
   * Returns an object with:
   *   - vulnerabilities: array of { name, description, packages[] }
   *   - malwareMap: Map of packageName -> { compromisedVersions, description, severity, vulnerability }
   */
  parse (content) {
    const lines = content.split('\n')
    const vulnerabilities = []
    const malwareMap = new Map()

    let currentVulnerability = null
    let headerLines = []

    for (const line of lines) {
      const trimmed = line.trim()

      // Skip empty lines
      if (!trimmed) continue

      // Detect section headers (lines of === are section boundaries)
      if (trimmed.match(/^#\s*=+$/)) {
        // If we have collected header lines, create a new vulnerability section
        if (headerLines.length > 0) {
          const sectionInfo = this.parseSectionHeader(headerLines)
          if (sectionInfo) {
            currentVulnerability = {
              name: sectionInfo.name,
              description: sectionInfo.description,
              severity: 'critical',
              packages: []
            }
            vulnerabilities.push(currentVulnerability)
          }
          headerLines = []
        }
        continue
      }

      // Collect comment lines that might be section headers
      if (trimmed.startsWith('#')) {
        headerLines.push(trimmed)
        continue
      }

      // Package entry line - parse it
      const packageEntry = this.parsePackageLine(trimmed)
      if (packageEntry) {
        // Only process npm packages (bare entries or npm: prefixed)
        if (packageEntry.ecosystem === 'npm') {
          if (!currentVulnerability) {
            currentVulnerability = {
              name: 'Unknown Attack',
              description: 'Compromised packages',
              severity: 'critical',
              packages: []
            }
            vulnerabilities.push(currentVulnerability)
          }

          currentVulnerability.packages.push(packageEntry)

          // Add to malware map
          if (malwareMap.has(packageEntry.name)) {
            const existing = malwareMap.get(packageEntry.name)
            if (!existing.compromisedVersions.includes(packageEntry.version)) {
              existing.compromisedVersions.push(packageEntry.version)
            }
          } else {
            malwareMap.set(packageEntry.name, {
              compromisedVersions: [packageEntry.version],
              description: `Part of ${currentVulnerability.name}`,
              severity: 'critical',
              vulnerability: currentVulnerability.name
            })
          }
        }
      }
    }

    return { vulnerabilities, malwareMap }
  }

  /**
   * Parse section header comment lines into a name and description
   */
  parseSectionHeader (commentLines) {
    // Look for the main header line pattern like:
    // # SEPTEMBER 8, 2025 - CHALK/DEBUG CRYPTO THEFT ATTACK (18+ packages)
    // # MARCH 2026 - AXIOS SUPPLY CHAIN ATTACK (3 packages)
    for (const line of commentLines) {
      const headerMatch = line.match(/^#\s*(.+?\d{4})\s*[-–—]\s*(.+)$/)
      if (headerMatch) {
        const date = headerMatch[1].trim()
        const attackName = headerMatch[2].trim()
        const name = `${date} - ${attackName}`

        // Collect remaining lines as description
        const descLines = commentLines
          .filter(l => l !== line && !l.match(/^#\s*=+$/) && !l.match(/^#\s*Source/))
          .map(l => l.replace(/^#\s*/, ''))
          .filter(l => l.length > 0)
          .slice(0, 3)

        const description = descLines.join(' ').substring(0, 200) || attackName

        return { name, description }
      }
    }

    return null
  }

  /**
   * Parse a single package line
   * Formats: package_name:version, npm:package_name:version, pypi:package_name:version
   * Scoped packages: @scope/package:version or npm:@scope/package:version
   */
  parsePackageLine (line) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) return null

    // Check for ecosystem prefix
    const ecosystemPrefixes = ['npm:', 'pypi:', 'composer:', 'crates:']
    let ecosystem = 'npm'
    let rest = trimmed

    for (const prefix of ecosystemPrefixes) {
      if (trimmed.startsWith(prefix)) {
        ecosystem = prefix.slice(0, -1)
        rest = trimmed.slice(prefix.length)
        break
      }
    }

    // Handle composer format: vendor/package:version
    if (ecosystem === 'composer') {
      const lastColon = rest.lastIndexOf(':')
      if (lastColon === -1) return null
      return {
        ecosystem,
        name: rest.substring(0, lastColon),
        version: rest.substring(lastColon + 1)
      }
    }

    // Handle scoped packages: @scope/package:version
    // Split on the LAST colon to get name and version
    const lastColon = rest.lastIndexOf(':')
    if (lastColon === -1) return null

    const name = rest.substring(0, lastColon)
    const version = rest.substring(lastColon + 1)

    if (!name || !version) return null

    return { ecosystem, name, version }
  }

  /**
   * Download and parse the compromised packages list
   * Returns data compatible with DependencyChecker
   */
  async load () {
    console.log('Downloading compromised packages list from remote source...')
    console.log(`  URL: ${this.url}`)

    const content = await this.download()
    const { vulnerabilities, malwareMap } = this.parse(content)

    // Count npm packages
    const npmVulns = vulnerabilities.filter(v => v.packages.length > 0)

    console.log('  ✓ Downloaded and parsed successfully')
    console.log(`  ✓ Found ${npmVulns.length} attack campaign(s)`)
    console.log(`  ✓ Total: ${malwareMap.size} unique compromised npm package(s)\n`)

    return { vulnerabilities, malwareMap }
  }
}

module.exports = CompromisedPackagesLoader
