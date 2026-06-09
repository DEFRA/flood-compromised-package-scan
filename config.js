require('dotenv').config()

module.exports = {
  // GitHub API configuration
  githubToken: process.env.GITHUB_TOKEN,

  // List of repositories to scan
  // Format: { owner: 'username', repo: 'repository-name' }
  repositories: [
    { owner: 'defra', repo: 'flood-app' }//,
    // { owner: 'defra', repo: 'flood-service' },
    // { owner: 'defra', repo: 'flood-db' },
    // { owner: 'defra', repo: 'flood-gis' },
    // { owner: 'defra', repo: 'flood-webchat' },
    // { owner: 'defra', repo: 'cap-xml' },
    // { owner: 'defra', repo: 'cap-xml-db' },
    // { owner: 'defra', repo: 'fws-app' },
    // { owner: 'defra', repo: 'fws-api' },
    // { owner: 'defra', repo: 'fws-db' },
    // { owner: 'defra', repo: 'flood-data' },
    // { owner: 'defra', repo: 'flood-service-tests-v2' },
    // { owner: 'defra', repo: 'cap-xml-tests' }
  ],

  // Compromised packages list URL (remote text file)
  compromisedPackagesUrl: 'https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt',

  // Files to check in each repository
  targetFiles: ['package.json', 'package-lock.json'],

  // Maximum number of branches to scan per repository (0 = all branches)
  maxBranchesPerRepo: 0,

  // API rate limit settings
  apiRateLimit: {
    enabled: true,
    requestsPerHour: 5000
  }
}
