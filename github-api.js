const { Octokit } = require('octokit')

class GitHubAPI {
  constructor (token) {
    if (!token) {
      throw new Error('GitHub token is required. Please set GITHUB_TOKEN in .env file')
    }
    this.octokit = new Octokit({
      auth: token,
      headers: {
        'X-GitHub-Api-Version': '2022-11-28'
      }
    })
  }

  /**
   * Get all branches for a repository
   */
  async getBranches (owner, repo) {
    try {
      const branches = []
      let page = 1
      let hasMore = true

      while (hasMore) {
        const response = await this.octokit.rest.repos.listBranches({
          owner,
          repo,
          per_page: 100,
          page
        })

        branches.push(...response.data)
        hasMore = response.data.length === 100
        page++
      }

      return branches.map(branch => branch.name)
    } catch (error) {
      console.error(`Error fetching branches for ${owner}/${repo}:`, error.message)
      return []
    }
  }

  /**
   * Get file content from a specific branch
   */
  async getFileContent (owner, repo, path, branch) {
    try {
      const response = await this.octokit.rest.repos.getContent({
        owner,
        repo,
        path,
        ref: branch
      })

      // Decode base64 content
      if (response.data.content) {
        return Buffer.from(response.data.content, 'base64').toString('utf-8')
      }
      return null
    } catch (error) {
      // File doesn't exist on this branch
      if (error.status === 404) {
        return null
      }
      console.error(`Error fetching ${path} from ${owner}/${repo}@${branch}:`, error.message)
      return null
    }
  }

  /**
   * Find all paths matching target filenames in a branch using the Git Tree API
   */
  async findFiles (owner, repo, branch, filenames) {
    try {
      const response = await this.octokit.rest.git.getTree({
        owner,
        repo,
        tree_sha: branch,
        recursive: 'true'
      })

      const matchingPaths = response.data.tree
        .filter(item => item.type === 'blob' && filenames.includes(item.path.split('/').pop()))
        .map(item => item.path)

      return matchingPaths
    } catch (error) {
      console.error(`Error fetching tree for ${owner}/${repo}@${branch}:`, error.message)
      return []
    }
  }

  /**
   * Search for files in a repository
   */
  async searchFiles (owner, repo, filename, branch) {
    try {
      const query = `filename:${filename} repo:${owner}/${repo}`
      const response = await this.octokit.rest.search.code({
        q: query,
        per_page: 100
      })

      return response.data.items.map(item => item.path)
    } catch (error) {
      console.error(`Error searching for ${filename} in ${owner}/${repo}:`, error.message)
      return []
    }
  }

  /**
   * Check API rate limit status
   */
  async checkRateLimit () {
    try {
      const response = await this.octokit.rest.rateLimit.get()
      return {
        limit: response.data.rate.limit,
        remaining: response.data.rate.remaining,
        reset: new Date(response.data.rate.reset * 1000)
      }
    } catch (error) {
      console.error('Error checking rate limit:', error.message)
      return null
    }
  }
}

module.exports = GitHubAPI
