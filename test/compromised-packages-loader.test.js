const CompromisedPackagesLoader = require('../compromised-packages-loader')

describe('CompromisedPackagesLoader', () => {
  describe('parsePackageLine', () => {
    let loader

    beforeEach(() => {
      loader = new CompromisedPackagesLoader()
    })

    it('should parse a bare package:version entry as npm', () => {
      const result = loader.parsePackageLine('axios:1.14.1')
      expect(result).toEqual({ ecosystem: 'npm', name: 'axios', version: '1.14.1' })
    })

    it('should parse a scoped package entry', () => {
      const result = loader.parsePackageLine('@tanstack/react-router:1.169.5')
      expect(result).toEqual({ ecosystem: 'npm', name: '@tanstack/react-router', version: '1.169.5' })
    })

    it('should parse an npm-prefixed entry', () => {
      const result = loader.parsePackageLine('npm:chalk:5.6.1')
      expect(result).toEqual({ ecosystem: 'npm', name: 'chalk', version: '5.6.1' })
    })

    it('should parse a pypi-prefixed entry', () => {
      const result = loader.parsePackageLine('pypi:litellm:1.82.7')
      expect(result).toEqual({ ecosystem: 'pypi', name: 'litellm', version: '1.82.7' })
    })

    it('should parse a composer entry with vendor/package', () => {
      const result = loader.parsePackageLine('composer:laravel-lang/lang:15.29.5')
      expect(result).toEqual({ ecosystem: 'composer', name: 'laravel-lang/lang', version: '15.29.5' })
    })

    it('should return null for comment lines', () => {
      const result = loader.parsePackageLine('# this is a comment')
      expect(result).toBeNull()
    })

    it('should return null for empty lines', () => {
      const result = loader.parsePackageLine('')
      expect(result).toBeNull()
    })

    it('should return null for lines without a colon', () => {
      const result = loader.parsePackageLine('some-package-no-version')
      expect(result).toBeNull()
    })
  })

  describe('parseSectionHeader', () => {
    let loader

    beforeEach(() => {
      loader = new CompromisedPackagesLoader()
    })

    it('should parse a standard section header', () => {
      const lines = [
        '# MARCH 2026 - AXIOS SUPPLY CHAIN ATTACK (3 packages)',
        '# Compromised axios maintainer account injects plain-crypto-js RAT dropper'
      ]
      const result = loader.parseSectionHeader(lines)
      expect(result).not.toBeNull()
      expect(result.name).toBe('MARCH 2026 - AXIOS SUPPLY CHAIN ATTACK (3 packages)')
      expect(result.description).toContain('Compromised axios maintainer')
    })

    it('should parse headers with en-dash separator', () => {
      const lines = [
        '# SEPTEMBER 8, 2025 – CHALK CRYPTO THEFT (18 packages)'
      ]
      const result = loader.parseSectionHeader(lines)
      expect(result).not.toBeNull()
      expect(result.name).toContain('SEPTEMBER 8, 2025')
      expect(result.name).toContain('CHALK CRYPTO THEFT')
    })

    it('should return null when no date pattern is found', () => {
      const lines = [
        '# Just a random comment',
        '# No date here'
      ]
      const result = loader.parseSectionHeader(lines)
      expect(result).toBeNull()
    })
  })

  describe('parse', () => {
    let loader

    beforeEach(() => {
      loader = new CompromisedPackagesLoader()
    })

    it('should parse a complete section with packages', () => {
      const content = `# Some preamble comment
#
# ========================================================================
# MARCH 2026 - AXIOS SUPPLY CHAIN ATTACK (3 packages)
# Compromised axios maintainer account
# ========================================================================
axios:1.14.1
axios:0.30.4
plain-crypto-js:4.2.1
`
      const { vulnerabilities, malwareMap } = loader.parse(content)

      expect(vulnerabilities.length).toBe(1)
      expect(vulnerabilities[0].name).toContain('MARCH 2026')
      expect(vulnerabilities[0].packages.length).toBe(3)

      expect(malwareMap.has('axios')).toBe(true)
      expect(malwareMap.get('axios').compromisedVersions).toEqual(['1.14.1', '0.30.4'])
      expect(malwareMap.has('plain-crypto-js')).toBe(true)
    })

    it('should group multiple versions of the same package', () => {
      const content = `# ========================================================================
# MAY 2026 - TEST ATTACK (2 packages)
# Test description
# ========================================================================
@scope/pkg:1.0.0
@scope/pkg:2.0.0
other-pkg:3.0.0
`
      const { malwareMap } = loader.parse(content)

      expect(malwareMap.get('@scope/pkg').compromisedVersions).toEqual(['1.0.0', '2.0.0'])
      expect(malwareMap.get('other-pkg').compromisedVersions).toEqual(['3.0.0'])
    })

    it('should skip pypi entries from the malware map', () => {
      const content = `# ========================================================================
# MARCH 2026 - CROSS ECOSYSTEM ATTACK (2 packages)
# Targets both npm and pypi
# ========================================================================
axios:1.14.1
pypi:litellm:1.82.7
`
      const { malwareMap } = loader.parse(content)

      expect(malwareMap.has('axios')).toBe(true)
      expect(malwareMap.has('litellm')).toBe(false)
    })

    it('should handle multiple attack sections', () => {
      const content = `# ========================================================================
# SEPTEMBER 2025 - FIRST ATTACK (1 package)
# First attack desc
# ========================================================================
chalk:5.6.1

# ========================================================================
# MARCH 2026 - SECOND ATTACK (1 package)
# Second attack desc
# ========================================================================
axios:1.14.1
`
      const { vulnerabilities, malwareMap } = loader.parse(content)

      expect(vulnerabilities.length).toBe(2)
      expect(malwareMap.get('chalk').vulnerability).toContain('SEPTEMBER 2025')
      expect(malwareMap.get('axios').vulnerability).toContain('MARCH 2026')
    })
  })
})
