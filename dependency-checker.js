const fs = require('fs')
const path = require('path')
const semver = require('semver')

class DependencyChecker {
  constructor (malwareDbPath) {
    this.vulnerabilityStats = []
    this.malwareDb = malwareDbPath ? this.loadMalwareDb(malwareDbPath) : new Map()
  }

  /**
   * Load malware database from remotely downloaded and parsed data
   * @param {Object} remoteData - { vulnerabilities, malwareMap } from CompromisedPackagesLoader
   */
  loadFromRemoteData (remoteData) {
    this.malwareDb = remoteData.malwareMap

    this.vulnerabilityStats = remoteData.vulnerabilities
      .filter(v => v.packages.length > 0)
      .map(v => ({
        name: v.name,
        description: v.description,
        packageCount: v.packages.length,
        severity: v.severity || 'critical'
      }))
  }

  /**
   * Load malware database from JSON file(s)
   * Can accept either a single file path or a directory containing multiple JSON files
   */
  loadMalwareDb (dbPath) {
    const malwareMap = new Map()
    const vulnerabilities = []
    let fileCount = 0

    try {
      const stats = fs.statSync(dbPath)

      if (stats.isDirectory()) {
        // Load all JSON files from directory
        const files = fs.readdirSync(dbPath)
          .filter(file => file.endsWith('.json'))

        console.log(`Loading malware databases from ${dbPath}...`)

        files.forEach(file => {
          const filePath = path.join(dbPath, file)
          try {
            const data = fs.readFileSync(filePath, 'utf-8')
            const db = JSON.parse(data)

            if (db.compromisedPackages && Array.isArray(db.compromisedPackages)) {
              db.compromisedPackages.forEach(pkg => {
                malwareMap.set(pkg.name, {
                  compromisedVersions: pkg.compromisedVersions,
                  description: pkg.description,
                  severity: pkg.severity,
                  vulnerability: db.vulnerability || 'unknown'
                })
              })

              // Track vulnerability stats
              vulnerabilities.push({
                name: db.vulnerability || 'unknown',
                description: db.description || '',
                packageCount: db.compromisedPackages.length,
                severity: db.severity || 'critical'
              })

              fileCount++
              console.log(`  ✓ Loaded ${file}: ${db.compromisedPackages.length} package(s) from ${db.vulnerability || 'unknown vulnerability'}`)
            }
          } catch (error) {
            console.error(`  ✗ Error loading ${file}:`, error.message)
          }
        })

        console.log(`Total: ${malwareMap.size} unique compromised package(s) from ${fileCount} database(s)\n`)
      } else {
        // Single file - backward compatibility
        const data = fs.readFileSync(dbPath, 'utf-8')
        const db = JSON.parse(data)

        if (db.compromisedPackages && Array.isArray(db.compromisedPackages)) {
          db.compromisedPackages.forEach(pkg => {
            malwareMap.set(pkg.name, {
              compromisedVersions: pkg.compromisedVersions,
              description: pkg.description,
              severity: pkg.severity,
              vulnerability: db.vulnerability || 'unknown'
            })
          })

          vulnerabilities.push({
            name: db.vulnerability || 'unknown',
            description: db.description || '',
            packageCount: db.compromisedPackages.length,
            severity: db.severity || 'critical'
          })
        }
      }

      this.vulnerabilityStats = vulnerabilities
      return malwareMap
    } catch (error) {
      console.error('Error loading malware database:', error.message)
      return new Map()
    }
  }

  /**
   * Get vulnerability statistics
   */
  getVulnerabilityStats () {
    return this.vulnerabilityStats
  }

  /**
   * Check if a package version is compromised
   */
  isVersionCompromised (packageName, version, compromisedVersions) {
    // If all versions are compromised
    if (compromisedVersions.includes('*')) {
      return true
    }

    // Clean version string
    const cleanVersion = semver.clean(version)
    if (!cleanVersion) {
      // If version can't be parsed, check for exact match
      return compromisedVersions.includes(version)
    }

    // Check if any compromised version matches
    return compromisedVersions.some(cv => {
      const cleanCompromisedVersion = semver.clean(cv)
      if (!cleanCompromisedVersion) {
        return cv === version
      }
      return semver.eq(cleanVersion, cleanCompromisedVersion)
    })
  }

  /**
   * Analyze package.json or package-lock.json content
   */
  analyzeDependencies (content, filename) {
    try {
      const data = JSON.parse(content)
      const results = {
        compromised: [],
        packagePresent: [],
        safe: true
      }

      let dependencies = {}

      // Extract dependencies based on file type
      if (filename === 'package.json') {
        dependencies = {
          ...data.dependencies,
          ...data.devDependencies,
          ...data.peerDependencies,
          ...data.optionalDependencies
        }
      } else if (filename === 'package-lock.json') {
        // For package-lock.json v1
        if (data.dependencies) {
          dependencies = data.dependencies
        }
        // For package-lock.json v2+
        if (data.packages) {
          Object.keys(data.packages).forEach(key => {
            if (key !== '' && data.packages[key].version) {
              const pkgName = key.replace(/^node_modules\//, '')
              dependencies[pkgName] = data.packages[key].version
            }
          })
        }
      }

      // Check each dependency
      for (const [pkgName, versionInfo] of Object.entries(dependencies)) {
        if (this.malwareDb.has(pkgName)) {
          const malwareInfo = this.malwareDb.get(pkgName)
          const version = typeof versionInfo === 'string'
            ? versionInfo
            : versionInfo.version

          const isCompromised = this.isVersionCompromised(
            pkgName,
            version,
            malwareInfo.compromisedVersions
          )

          if (isCompromised) {
            results.compromised.push({
              package: pkgName,
              version,
              severity: malwareInfo.severity,
              description: malwareInfo.description,
              compromisedVersions: malwareInfo.compromisedVersions
            })
            results.safe = false
          } else {
            results.packagePresent.push({
              package: pkgName,
              version,
              compromisedVersions: malwareInfo.compromisedVersions,
              status: 'Package present but version is safe'
            })
          }
        }
      }

      return results
    } catch (error) {
      console.error(`Error analyzing dependencies in ${filename}:`, error.message)
      return {
        compromised: [],
        packagePresent: [],
        safe: true,
        error: error.message
      }
    }
  }

  /**
   * Generate a summary report for a single file
   */
  generateFileReport (results, filename) {
    const report = {
      filename,
      status: results.safe ? 'SAFE' : 'COMPROMISED',
      compromisedCount: results.compromised.length,
      packagePresentCount: results.packagePresent.length,
      details: {
        compromised: results.compromised,
        packagePresent: results.packagePresent
      }
    }

    return report
  }
}

module.exports = DependencyChecker
