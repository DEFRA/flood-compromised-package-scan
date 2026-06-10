const Scanner = require('../scanner')

// Mock the dependencies
jest.mock('../github-api')
jest.mock('../compromised-packages-loader')

const GitHubAPI = require('../github-api')
const CompromisedPackagesLoader = require('../compromised-packages-loader')

describe('Scanner', () => {
  let scanner
  let mockConfig

  const malwareMap = new Map([
    ['axios', { compromisedVersions: ['1.14.1'], description: 'Compromised axios', severity: 'critical', vulnerability: 'AXIOS ATTACK' }],
    ['chalk', { compromisedVersions: ['5.6.1'], description: 'Part of Shai-Hulud', severity: 'critical', vulnerability: 'SHAI-HULUD' }]
  ])

  const mockRemoteData = {
    vulnerabilities: [
      { name: 'AXIOS ATTACK', description: 'Axios compromise', severity: 'critical', packages: [{ ecosystem: 'npm', name: 'axios', version: '1.14.1' }] },
      { name: 'SHAI-HULUD', description: 'Shai-Hulud worm', severity: 'critical', packages: [{ ecosystem: 'npm', name: 'chalk', version: '5.6.1' }] }
    ],
    malwareMap
  }

  beforeEach(() => {
    jest.clearAllMocks()

    mockConfig = {
      githubToken: 'fake-token',
      compromisedPackagesUrl: 'https://example.com/packages.txt',
      repositories: [{ owner: 'defra', repo: 'flood-app' }],
      targetFiles: ['package.json', 'package-lock.json'],
      maxBranchesPerRepo: 0
    }

    // Mock CompromisedPackagesLoader
    CompromisedPackagesLoader.mockImplementation(() => ({
      load: jest.fn().mockResolvedValue(mockRemoteData)
    }))

    // Mock GitHubAPI
    GitHubAPI.mockImplementation(() => ({
      checkRateLimit: jest.fn().mockResolvedValue({ remaining: 4999, limit: 5000, reset: new Date() }),
      getBranches: jest.fn().mockResolvedValue(['main']),
      findFiles: jest.fn().mockResolvedValue(['package.json']),
      getFileContent: jest.fn().mockResolvedValue(null)
    }))

    scanner = new Scanner(mockConfig)
  })

  describe('run', () => {
    it('should download compromised packages list before scanning', async () => {
      const mockLoad = jest.fn().mockResolvedValue(mockRemoteData)
      scanner.loader = { load: mockLoad }
      scanner.githubApi.getBranches = jest.fn().mockResolvedValue(['main'])
      scanner.githubApi.findFiles = jest.fn().mockResolvedValue(['package.json'])
      scanner.githubApi.getFileContent = jest.fn().mockResolvedValue(JSON.stringify({
        dependencies: { express: '4.18.2' }
      }))
      scanner.githubApi.checkRateLimit = jest.fn().mockResolvedValue({ remaining: 5000, limit: 5000, reset: new Date() })

      await scanner.run()

      expect(mockLoad).toHaveBeenCalledTimes(1)
    })

    it('should detect a compromised package across a branch', async () => {
      scanner.loader = { load: jest.fn().mockResolvedValue(mockRemoteData) }
      scanner.githubApi.checkRateLimit = jest.fn().mockResolvedValue({ remaining: 5000, limit: 5000, reset: new Date() })
      scanner.githubApi.getBranches = jest.fn().mockResolvedValue(['main'])
      scanner.githubApi.findFiles = jest.fn().mockResolvedValue(['package.json'])
      scanner.githubApi.getFileContent = jest.fn().mockResolvedValue(JSON.stringify({
        dependencies: { axios: '1.14.1', express: '4.18.2' }
      }))

      const report = await scanner.run()

      expect(report.results.length).toBe(1)
      expect(report.results[0].overallStatus).toBe('COMPROMISED')
      expect(report.results[0].files[0].status).toBe('COMPROMISED')
      expect(report.results[0].files[0].details.compromised[0].package).toBe('axios')
    })

    it('should report SAFE when no compromised packages found', async () => {
      scanner.loader = { load: jest.fn().mockResolvedValue(mockRemoteData) }
      scanner.githubApi.checkRateLimit = jest.fn().mockResolvedValue({ remaining: 5000, limit: 5000, reset: new Date() })
      scanner.githubApi.getBranches = jest.fn().mockResolvedValue(['main'])
      scanner.githubApi.findFiles = jest.fn().mockResolvedValue(['package.json'])
      scanner.githubApi.getFileContent = jest.fn().mockResolvedValue(JSON.stringify({
        dependencies: { express: '4.18.2', lodash: '4.17.21' }
      }))

      const report = await scanner.run()

      expect(report.results[0].overallStatus).toBe('SAFE')
    })

    it('should scan multiple files found in monorepo', async () => {
      scanner.loader = { load: jest.fn().mockResolvedValue(mockRemoteData) }
      scanner.githubApi.checkRateLimit = jest.fn().mockResolvedValue({ remaining: 5000, limit: 5000, reset: new Date() })
      scanner.githubApi.getBranches = jest.fn().mockResolvedValue(['main'])
      scanner.githubApi.findFiles = jest.fn().mockResolvedValue([
        'package.json',
        'packages/api/package.json',
        'packages/web/package.json'
      ])
      scanner.githubApi.getFileContent = jest.fn()
        .mockResolvedValueOnce(JSON.stringify({ dependencies: { express: '4.18.2' } }))
        .mockResolvedValueOnce(JSON.stringify({ dependencies: { axios: '1.14.1' } }))
        .mockResolvedValueOnce(JSON.stringify({ dependencies: { chalk: '5.6.1' } }))

      const report = await scanner.run()

      expect(report.results[0].files.length).toBe(3)
      expect(report.results[0].overallStatus).toBe('COMPROMISED')
      expect(report.results[0].compromisedFiles).toBe(2)
      expect(report.results[0].safeFiles).toBe(1)
    })

    it('should scan multiple branches', async () => {
      scanner.loader = { load: jest.fn().mockResolvedValue(mockRemoteData) }
      scanner.githubApi.checkRateLimit = jest.fn().mockResolvedValue({ remaining: 5000, limit: 5000, reset: new Date() })
      scanner.githubApi.getBranches = jest.fn().mockResolvedValue(['main', 'develop', 'feature/bad-dep'])
      scanner.githubApi.findFiles = jest.fn().mockResolvedValue(['package.json'])
      scanner.githubApi.getFileContent = jest.fn()
        .mockResolvedValueOnce(JSON.stringify({ dependencies: { express: '4.18.2' } }))
        .mockResolvedValueOnce(JSON.stringify({ dependencies: { express: '4.18.2' } }))
        .mockResolvedValueOnce(JSON.stringify({ dependencies: { axios: '1.14.1' } }))

      const report = await scanner.run()

      expect(report.results.length).toBe(3)
      expect(report.summary.safeBranches).toBe(2)
      expect(report.summary.compromisedBranches).toBe(1)
    })

    it('should handle branches with no package files', async () => {
      scanner.loader = { load: jest.fn().mockResolvedValue(mockRemoteData) }
      scanner.githubApi.checkRateLimit = jest.fn().mockResolvedValue({ remaining: 5000, limit: 5000, reset: new Date() })
      scanner.githubApi.getBranches = jest.fn().mockResolvedValue(['docs-only-branch'])
      scanner.githubApi.findFiles = jest.fn().mockResolvedValue([])

      const report = await scanner.run()

      expect(report.results[0].missingFiles).toBe(1)
      expect(report.results[0].overallStatus).toBe('SAFE')
    })
  })

  describe('scanBranch - false positive prevention', () => {
    it('should NOT flag a safe version of a known package as compromised', async () => {
      scanner.loader = { load: jest.fn().mockResolvedValue(mockRemoteData) }
      scanner.githubApi.checkRateLimit = jest.fn().mockResolvedValue({ remaining: 5000, limit: 5000, reset: new Date() })
      scanner.githubApi.getBranches = jest.fn().mockResolvedValue(['main'])
      scanner.githubApi.findFiles = jest.fn().mockResolvedValue(['package.json'])
      // axios 1.6.0 is NOT compromised - only 1.14.1 is
      scanner.githubApi.getFileContent = jest.fn().mockResolvedValue(JSON.stringify({
        dependencies: { axios: '1.6.0' }
      }))

      const report = await scanner.run()

      expect(report.results[0].overallStatus).toBe('SAFE')
      expect(report.results[0].files[0].status).toBe('SAFE')
      expect(report.results[0].files[0].details.compromised.length).toBe(0)
      // But it should note the package is present
      expect(report.results[0].files[0].details.packagePresent.length).toBe(1)
      expect(report.results[0].files[0].details.packagePresent[0].package).toBe('axios')
    })

    it('should NOT flag packages not in the compromised list at all', async () => {
      scanner.loader = { load: jest.fn().mockResolvedValue(mockRemoteData) }
      scanner.githubApi.checkRateLimit = jest.fn().mockResolvedValue({ remaining: 5000, limit: 5000, reset: new Date() })
      scanner.githubApi.getBranches = jest.fn().mockResolvedValue(['main'])
      scanner.githubApi.findFiles = jest.fn().mockResolvedValue(['package.json'])
      scanner.githubApi.getFileContent = jest.fn().mockResolvedValue(JSON.stringify({
        dependencies: {
          express: '4.18.2',
          lodash: '4.17.21',
          hapi: '21.3.0',
          'some-random-pkg': '1.0.0'
        }
      }))

      const report = await scanner.run()

      expect(report.results[0].overallStatus).toBe('SAFE')
      expect(report.results[0].files[0].details.compromised.length).toBe(0)
      expect(report.results[0].files[0].details.packagePresent.length).toBe(0)
    })
  })

  describe('generateSummaryReport', () => {
    it('should include vulnerability campaign names in the report', async () => {
      scanner.loader = { load: jest.fn().mockResolvedValue(mockRemoteData) }
      scanner.githubApi.checkRateLimit = jest.fn().mockResolvedValue({ remaining: 5000, limit: 5000, reset: new Date() })
      scanner.githubApi.getBranches = jest.fn().mockResolvedValue(['main'])
      scanner.githubApi.findFiles = jest.fn().mockResolvedValue(['package.json'])
      scanner.githubApi.getFileContent = jest.fn().mockResolvedValue(JSON.stringify({
        dependencies: { axios: '1.14.1' }
      }))

      await scanner.run()
      const summaryReport = scanner.generateSummaryReport()

      expect(summaryReport).toContain('AXIOS ATTACK')
      expect(summaryReport).toContain('SHAI-HULUD')
      expect(summaryReport).toContain('COMPROMISED')
      expect(summaryReport).toContain('defra/flood-app')
    })
  })
})
