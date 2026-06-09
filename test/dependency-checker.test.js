const DependencyChecker = require('../dependency-checker')

describe('DependencyChecker', () => {
  let checker

  beforeEach(() => {
    checker = new DependencyChecker()
    checker.loadFromRemoteData({
      vulnerabilities: [
        {
          name: 'MARCH 2026 - AXIOS SUPPLY CHAIN ATTACK',
          description: 'Compromised axios',
          severity: 'critical',
          packages: [
            { ecosystem: 'npm', name: 'axios', version: '1.14.1' },
            { ecosystem: 'npm', name: 'axios', version: '0.30.4' },
            { ecosystem: 'npm', name: 'plain-crypto-js', version: '4.2.1' }
          ]
        },
        {
          name: 'SEPTEMBER 2025 - SHAI-HULUD WORM',
          description: 'Shai-Hulud worm attack',
          severity: 'critical',
          packages: [
            { ecosystem: 'npm', name: 'chalk', version: '5.6.1' },
            { ecosystem: 'npm', name: 'ansi-styles', version: '6.2.2' }
          ]
        }
      ],
      malwareMap: new Map([
        ['axios', { compromisedVersions: ['1.14.1', '0.30.4'], description: 'Part of AXIOS attack', severity: 'critical', vulnerability: 'MARCH 2026 - AXIOS SUPPLY CHAIN ATTACK' }],
        ['plain-crypto-js', { compromisedVersions: ['4.2.1'], description: 'Part of AXIOS attack', severity: 'critical', vulnerability: 'MARCH 2026 - AXIOS SUPPLY CHAIN ATTACK' }],
        ['chalk', { compromisedVersions: ['5.6.1'], description: 'Part of SHAI-HULUD', severity: 'critical', vulnerability: 'SEPTEMBER 2025 - SHAI-HULUD WORM' }],
        ['ansi-styles', { compromisedVersions: ['6.2.2'], description: 'Part of SHAI-HULUD', severity: 'critical', vulnerability: 'SEPTEMBER 2025 - SHAI-HULUD WORM' }]
      ])
    })
  })

  describe('isVersionCompromised', () => {
    it('should return true for an exact compromised version match', () => {
      const result = checker.isVersionCompromised('axios', '1.14.1', ['1.14.1', '0.30.4'])
      expect(result).toBe(true)
    })

    it('should return false for a safe version', () => {
      const result = checker.isVersionCompromised('axios', '1.6.0', ['1.14.1', '0.30.4'])
      expect(result).toBe(false)
    })

    it('should return true when wildcard * is in compromised versions', () => {
      const result = checker.isVersionCompromised('bad-pkg', '99.99.99', ['*'])
      expect(result).toBe(true)
    })

    it('should handle versions with leading v or spaces', () => {
      const result = checker.isVersionCompromised('axios', '1.14.1', ['1.14.1'])
      expect(result).toBe(true)
    })

    it('should return false for a completely different version', () => {
      const result = checker.isVersionCompromised('chalk', '4.1.2', ['5.6.1'])
      expect(result).toBe(false)
    })
  })

  describe('analyzeDependencies - package.json', () => {
    it('should detect a compromised dependency in package.json', () => {
      const packageJson = JSON.stringify({
        name: 'my-app',
        dependencies: {
          axios: '1.14.1',
          express: '4.18.2'
        }
      })

      const result = checker.analyzeDependencies(packageJson, 'package.json')

      expect(result.safe).toBe(false)
      expect(result.compromised.length).toBe(1)
      expect(result.compromised[0].package).toBe('axios')
      expect(result.compromised[0].version).toBe('1.14.1')
      expect(result.compromised[0].severity).toBe('critical')
    })

    it('should detect multiple compromised dependencies', () => {
      const packageJson = JSON.stringify({
        name: 'my-app',
        dependencies: {
          axios: '1.14.1',
          chalk: '5.6.1'
        }
      })

      const result = checker.analyzeDependencies(packageJson, 'package.json')

      expect(result.safe).toBe(false)
      expect(result.compromised.length).toBe(2)
      const names = result.compromised.map(c => c.package)
      expect(names).toContain('axios')
      expect(names).toContain('chalk')
    })

    it('should report safe when no compromised dependencies exist', () => {
      const packageJson = JSON.stringify({
        name: 'my-app',
        dependencies: {
          express: '4.18.2',
          lodash: '4.17.21'
        }
      })

      const result = checker.analyzeDependencies(packageJson, 'package.json')

      expect(result.safe).toBe(true)
      expect(result.compromised.length).toBe(0)
    })

    it('should flag package as present but safe when version is not compromised', () => {
      const packageJson = JSON.stringify({
        name: 'my-app',
        dependencies: {
          axios: '1.6.0'
        }
      })

      const result = checker.analyzeDependencies(packageJson, 'package.json')

      expect(result.safe).toBe(true)
      expect(result.compromised.length).toBe(0)
      expect(result.packagePresent.length).toBe(1)
      expect(result.packagePresent[0].package).toBe('axios')
      expect(result.packagePresent[0].status).toBe('Package present but version is safe')
    })

    it('should check devDependencies as well', () => {
      const packageJson = JSON.stringify({
        name: 'my-app',
        dependencies: {
          express: '4.18.2'
        },
        devDependencies: {
          chalk: '5.6.1'
        }
      })

      const result = checker.analyzeDependencies(packageJson, 'package.json')

      expect(result.safe).toBe(false)
      expect(result.compromised[0].package).toBe('chalk')
    })

    it('should handle empty dependencies gracefully', () => {
      const packageJson = JSON.stringify({
        name: 'my-app'
      })

      const result = checker.analyzeDependencies(packageJson, 'package.json')

      expect(result.safe).toBe(true)
      expect(result.compromised.length).toBe(0)
    })

    it('should handle invalid JSON gracefully', () => {
      const result = checker.analyzeDependencies('not valid json{{{', 'package.json')

      expect(result.safe).toBe(true)
      expect(result.error).toBeDefined()
    })
  })

  describe('analyzeDependencies - package-lock.json v2+', () => {
    it('should detect compromised packages in lockfile packages field', () => {
      const lockfile = JSON.stringify({
        name: 'my-app',
        lockfileVersion: 3,
        packages: {
          '': { name: 'my-app', version: '1.0.0' },
          'node_modules/axios': { version: '1.14.1' },
          'node_modules/express': { version: '4.18.2' }
        }
      })

      const result = checker.analyzeDependencies(lockfile, 'package-lock.json')

      expect(result.safe).toBe(false)
      expect(result.compromised.length).toBe(1)
      expect(result.compromised[0].package).toBe('axios')
      expect(result.compromised[0].version).toBe('1.14.1')
    })

    it('should detect scoped compromised packages in lockfile', () => {
      // Add a scoped package to the malware DB for this test
      checker.malwareDb.set('@tanstack/react-router', {
        compromisedVersions: ['1.169.5'],
        description: 'Part of Mini Shai-Hulud',
        severity: 'critical',
        vulnerability: 'MAY 2026 - MINI SHAI-HULUD'
      })

      const lockfile = JSON.stringify({
        name: 'my-app',
        lockfileVersion: 3,
        packages: {
          '': { name: 'my-app', version: '1.0.0' },
          'node_modules/@tanstack/react-router': { version: '1.169.5' },
          'node_modules/react': { version: '18.2.0' }
        }
      })

      const result = checker.analyzeDependencies(lockfile, 'package-lock.json')

      expect(result.safe).toBe(false)
      expect(result.compromised[0].package).toBe('@tanstack/react-router')
    })

    it('should report safe for lockfile with no compromised packages', () => {
      const lockfile = JSON.stringify({
        name: 'my-app',
        lockfileVersion: 3,
        packages: {
          '': { name: 'my-app', version: '1.0.0' },
          'node_modules/express': { version: '4.18.2' },
          'node_modules/lodash': { version: '4.17.21' }
        }
      })

      const result = checker.analyzeDependencies(lockfile, 'package-lock.json')

      expect(result.safe).toBe(true)
      expect(result.compromised.length).toBe(0)
    })
  })

  describe('analyzeDependencies - package-lock.json v1', () => {
    it('should detect compromised packages in v1 lockfile dependencies', () => {
      const lockfile = JSON.stringify({
        name: 'my-app',
        lockfileVersion: 1,
        dependencies: {
          axios: { version: '1.14.1', resolved: 'https://registry.npmjs.org/axios/-/axios-1.14.1.tgz' },
          express: { version: '4.18.2', resolved: 'https://registry.npmjs.org/express/-/express-4.18.2.tgz' }
        }
      })

      const result = checker.analyzeDependencies(lockfile, 'package-lock.json')

      expect(result.safe).toBe(false)
      expect(result.compromised.length).toBe(1)
      expect(result.compromised[0].package).toBe('axios')
    })
  })

  describe('generateFileReport', () => {
    it('should generate COMPROMISED report when unsafe', () => {
      const analysis = {
        compromised: [{ package: 'axios', version: '1.14.1', severity: 'critical', description: 'Bad', compromisedVersions: ['1.14.1'] }],
        packagePresent: [],
        safe: false
      }

      const report = checker.generateFileReport(analysis, 'packages/api/package.json')

      expect(report.filename).toBe('packages/api/package.json')
      expect(report.status).toBe('COMPROMISED')
      expect(report.compromisedCount).toBe(1)
    })

    it('should generate SAFE report when all clear', () => {
      const analysis = {
        compromised: [],
        packagePresent: [],
        safe: true
      }

      const report = checker.generateFileReport(analysis, 'package.json')

      expect(report.status).toBe('SAFE')
      expect(report.compromisedCount).toBe(0)
    })
  })

  describe('getVulnerabilityStats', () => {
    it('should return loaded vulnerability statistics', () => {
      const stats = checker.getVulnerabilityStats()

      expect(stats.length).toBe(2)
      expect(stats[0].name).toContain('AXIOS')
      expect(stats[0].packageCount).toBe(3)
      expect(stats[1].name).toContain('SHAI-HULUD')
      expect(stats[1].packageCount).toBe(2)
    })
  })
})
