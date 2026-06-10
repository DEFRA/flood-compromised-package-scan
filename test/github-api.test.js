const GitHubAPI = require('../github-api')

// Mock the octokit module
jest.mock('octokit', () => ({
  Octokit: jest.fn().mockImplementation(() => ({
    rest: {
      repos: {
        listBranches: jest.fn(),
        getContent: jest.fn()
      },
      git: {
        getTree: jest.fn()
      },
      rateLimit: {
        get: jest.fn()
      }
    }
  }))
}))

describe('GitHubAPI', () => {
  let api

  beforeEach(() => {
    api = new GitHubAPI('test-token')
  })

  describe('constructor', () => {
    it('should throw if no token provided', () => {
      expect(() => new GitHubAPI()).toThrow('GitHub token is required')
      expect(() => new GitHubAPI(null)).toThrow('GitHub token is required')
      expect(() => new GitHubAPI('')).toThrow('GitHub token is required')
    })

    it('should create instance with valid token', () => {
      const instance = new GitHubAPI('valid-token')
      expect(instance).toBeDefined()
      expect(instance.octokit).toBeDefined()
    })
  })

  describe('findFiles', () => {
    it('should return paths matching target filenames from the tree', async () => {
      api.octokit.rest.git.getTree.mockResolvedValue({
        data: {
          tree: [
            { path: 'package.json', type: 'blob' },
            { path: 'src/index.js', type: 'blob' },
            { path: 'packages/api/package.json', type: 'blob' },
            { path: 'packages/api/package-lock.json', type: 'blob' },
            { path: 'packages/web/package.json', type: 'blob' },
            { path: 'node_modules', type: 'tree' },
            { path: 'README.md', type: 'blob' }
          ],
          truncated: false
        }
      })

      const result = await api.findFiles('defra', 'flood-app', 'main', ['package.json', 'package-lock.json'])

      expect(result).toEqual([
        'package.json',
        'packages/api/package.json',
        'packages/api/package-lock.json',
        'packages/web/package.json'
      ])
    })

    it('should not include directories in results', async () => {
      api.octokit.rest.git.getTree.mockResolvedValue({
        data: {
          tree: [
            { path: 'package.json', type: 'blob' },
            { path: 'some-dir', type: 'tree' }
          ],
          truncated: false
        }
      })

      const result = await api.findFiles('defra', 'flood-app', 'main', ['package.json'])

      expect(result).toEqual(['package.json'])
    })

    it('should return empty array on error', async () => {
      api.octokit.rest.git.getTree.mockRejectedValue(new Error('Not found'))

      const result = await api.findFiles('defra', 'flood-app', 'bad-branch', ['package.json'])

      expect(result).toEqual([])
    })

    it('should return empty array when no matching files exist', async () => {
      api.octokit.rest.git.getTree.mockResolvedValue({
        data: {
          tree: [
            { path: 'README.md', type: 'blob' },
            { path: 'docs/guide.md', type: 'blob' }
          ],
          truncated: false
        }
      })

      const result = await api.findFiles('defra', 'flood-app', 'main', ['package.json', 'package-lock.json'])

      expect(result).toEqual([])
    })
  })

  describe('getFileContent', () => {
    it('should decode base64 content', async () => {
      const content = JSON.stringify({ name: 'test', dependencies: {} })
      api.octokit.rest.repos.getContent.mockResolvedValue({
        data: { content: Buffer.from(content).toString('base64') }
      })

      const result = await api.getFileContent('defra', 'flood-app', 'package.json', 'main')

      expect(result).toBe(content)
    })

    it('should return null for 404 errors', async () => {
      const error = new Error('Not Found')
      error.status = 404
      api.octokit.rest.repos.getContent.mockRejectedValue(error)

      const result = await api.getFileContent('defra', 'flood-app', 'package.json', 'missing-branch')

      expect(result).toBeNull()
    })

    it('should return null when content field is missing', async () => {
      api.octokit.rest.repos.getContent.mockResolvedValue({ data: {} })

      const result = await api.getFileContent('defra', 'flood-app', 'package.json', 'main')

      expect(result).toBeNull()
    })
  })

  describe('getBranches', () => {
    it('should return branch names', async () => {
      api.octokit.rest.repos.listBranches.mockResolvedValue({
        data: [
          { name: 'main' },
          { name: 'develop' },
          { name: 'feature/test' }
        ]
      })

      const result = await api.getBranches('defra', 'flood-app')

      expect(result).toEqual(['main', 'develop', 'feature/test'])
    })

    it('should return empty array on error', async () => {
      api.octokit.rest.repos.listBranches.mockRejectedValue(new Error('Forbidden'))

      const result = await api.getBranches('defra', 'flood-app')

      expect(result).toEqual([])
    })
  })
})
