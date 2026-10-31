/**
 * Action Doctor — GitHub Actions Client-Side Workflow Auditor Engine
 * Performs comprehensive security, supply-chain, runner, and best-practice checks.
 */

(function (global) {
  'use strict';

  // Severity Definitions
  const Severity = {
    CRITICAL: 'critical',
    ERROR: 'error',
    WARNING: 'warning',
    INFO: 'info'
  };

  const Category = {
    SECURITY: 'Security & Permissions',
    SUPPLY_CHAIN: 'Supply Chain & Pinning',
    RUNNERS: 'Runner Compatibility',
    BEST_PRACTICE: 'Best Practices & Hygiene'
  };

  // Known 40-character commit SHA pins and versions
  const KNOWN_ACTION_PINS = {
    'actions/checkout@v4': { sha: '11bd71901bbe5b1630ceea73d27597364c9af683', tag: 'v4.2.2' },
    'actions/checkout@v3': { sha: 'f43a0e5ff2bd294095638e18286ca9a3d1956744', tag: 'v3.6.0' },
    'actions/checkout@v2': { sha: '11bd71901bbe5b1630ceea73d27597364c9af683', tag: 'v4.2.2' },
    'actions/setup-python@v5': { sha: '42375524e23c412d93fb67b49958b491fce71c38', tag: 'v5.4.0' },
    'actions/setup-python@v4': { sha: '65d7f2d534ac1bc67fcd62888c5f4f3d2cb2b236', tag: 'v4.7.1' },
    'actions/setup-node@v4': { sha: '1e60f620b9541d16abce94cb522027ec595dacd5', tag: 'v4.2.0' },
    'actions/setup-node@v3': { sha: 'e33196f7421987e6884a0da4c67c8a8464455dd3', tag: 'v3.8.2' },
    'actions/setup-go@v5': { sha: 'f111f330730b5538a6e512304957eb1a1034d6f6', tag: 'v5.3.0' },
    'actions/setup-java@v4': { sha: '3a4f6e1af504cf6a31855fa899c6aa5355ba6c12', tag: 'v4.7.0' },
    'actions/cache@v4': { sha: 'd4323d4df104b026a6aa633fdb11d772146be0bf', tag: 'v4.2.2' },
    'actions/upload-artifact@v4': { sha: '4cec3d8aa04e39d1a68397de0c4cd6fb99baeddf', tag: 'v4.6.1' },
    'actions/download-artifact@v4': { sha: 'cc203385981b70ca67e1ab388640d04474e5dd81', tag: 'v4.1.9' },
    'actions/deploy-pages@v4': { sha: 'd6db90164ac5ed86f2b6aed7e0febac5b3c0c03e', tag: 'v4.0.5' },
    'actions/configure-pages@v5': { sha: '983d7736d9b0ae728b81ab479565c72886d7745b', tag: 'v5.0.0' },
    'actions/upload-pages-artifact@v3': { sha: '56afc609e74202658d3ffba0e8f6dda462b719fa', tag: 'v3.0.1' },
    'docker/setup-buildx-action@v3': { sha: 'b5ca514318bd6ebac0fb2aedd5d36ec1b5c232a2', tag: 'v3.10.0' },
    'docker/login-action@v3': { sha: '9780b0c442fbb1117ed29e0efdff1e18412f7567', tag: 'v3.3.0' },
    'docker/build-push-action@v5': { sha: '471d1dc4e07e5cdedd4c2171150001c434f0b7a4', tag: 'v5.0.0' }
  };

  const DEPRECATED_RUNNERS = {
    'ubuntu-18.04': { replacement: 'ubuntu-latest', retirement: 'April 2023' },
    'ubuntu-20.04': { replacement: 'ubuntu-22.04 or ubuntu-latest', retirement: 'April 2025' },
    'macos-10.15': { replacement: 'macos-13 or macos-latest', retirement: 'August 2022' },
    'macos-11': { replacement: 'macos-13 or macos-latest', retirement: 'June 2024' },
    'windows-2016': { replacement: 'windows-latest', retirement: 'March 2022' },
    'windows-2019': { replacement: 'windows-2022 or windows-latest', retirement: 'June 2025' }
  };

  const DEPRECATED_ACTIONS = {
    'actions/checkout@v1': 'Upgrade to actions/checkout@v4',
    'actions/checkout@v2': 'Upgrade to actions/checkout@v4 (v2 relies on deprecated Node 12 runtime)',
    'actions/setup-node@v1': 'Upgrade to actions/setup-node@v4',
    'actions/setup-node@v2': 'Upgrade to actions/setup-node@v4',
    'actions/setup-python@v1': 'Upgrade to actions/setup-python@v5',
    'actions/setup-python@v2': 'Upgrade to actions/setup-python@v5',
    'actions/cache@v1': 'Upgrade to actions/cache@v4',
    'actions/cache@v2': 'Upgrade to actions/cache@v4',
    'actions/upload-artifact@v1': 'Upgrade to actions/upload-artifact@v4',
    'actions/upload-artifact@v2': 'Upgrade to actions/upload-artifact@v4',
    'actions/upload-artifact@v3': 'Upgrade to actions/upload-artifact@v4'
  };

  const MUTABLE_BRANCHES = new Set(['main', 'master', 'dev', 'develop', 'latest', 'head', 'trunk', 'v1-branch']);

  // Untrusted GitHub context patterns vulnerable to script injection in run steps
  const UNTRUSTED_CONTEXT_PATTERNS = [
    { pattern: /\$\{\{\s*github\.event\.issue\.title\s*\}\}/i, name: 'github.event.issue.title' },
    { pattern: /\$\{\{\s*github\.event\.issue\.body\s*\}\}/i, name: 'github.event.issue.body' },
    { pattern: /\$\{\{\s*github\.event\.pull_request\.title\s*\}\}/i, name: 'github.event.pull_request.title' },
    { pattern: /\$\{\{\s*github\.event\.pull_request\.body\s*\}\}/i, name: 'github.event.pull_request.body' },
    { pattern: /\$\{\{\s*github\.event\.comment\.body\s*\}\}/i, name: 'github.event.comment.body' },
    { pattern: /\$\{\{\s*github\.event\.review\.body\s*\}\}/i, name: 'github.event.review.body' },
    { pattern: /\$\{\{\s*github\.head_ref\s*\}\}/i, name: 'github.head_ref' },
    { pattern: /\$\{\{\s*github\.event\.workflow_run\.head_branch\s*\}\}/i, name: 'github.event.workflow_run.head_branch' },
    { pattern: /\$\{\{\s*github\.event\.workflow_run\.head_commit\.message\s*\}\}/i, name: 'github.event.workflow_run.head_commit.message' },
    { pattern: /\$\{\{\s*github\.event\.client_payload\b/i, name: 'github.event.client_payload' }
  ];

  // Secrets detection in run commands
  const SECRET_PATTERNS = [
    { pattern: /\bghp_[A-Za-z0-9_]{36,}\b/, name: 'GitHub Personal Access Token (Classic)' },
    { pattern: /\bgithub_pat_[A-Za-z0-9_]{82}\b/, name: 'GitHub Fine-Grained Personal Access Token' },
    { pattern: /\bAKIA[0-9A-Z]{16}\b/, name: 'AWS Access Key ID' },
    { pattern: /-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA)?\s*PRIVATE\s+KEY-----/, name: 'Private SSH / SSL Key' }
  ];

  class ActionAuditor {
    constructor() {}

    /**
     * Parse YAML text using jsyaml
     */
    parseYaml(yamlText) {
      if (typeof jsyaml !== 'undefined') {
        try {
          return { data: jsyaml.load(yamlText), error: null };
        } catch (e) {
          return { data: null, error: e.message };
        }
      }
      return { data: null, error: 'YAML parser not loaded' };
    }

    /**
     * Audit a GitHub Actions workflow text
     * Returns structured findings, score, statistics, and remediation.
     */
    audit(rawYaml) {
      const lines = rawYaml.split(/\r?\n/);
      const parseResult = this.parseYaml(rawYaml);
      const parsed = parseResult.data || {};

      const issues = [];

      if (parseResult.error) {
        issues.push({
          id: 'AD000',
          name: 'yaml-syntax-error',
          category: Category.BEST_PRACTICE,
          severity: Severity.CRITICAL,
          line: 1,
          message: `YAML syntax error encountered: ${parseResult.error}`,
          recommendation: 'Fix invalid YAML syntax before proceeding with security audit.',
          remediation: null
        });
      }

      // 1. AD101: Missing Permissions
      this.checkMissingPermissions(parsed, lines, issues);

      // 2. AD102: Excessive Permissions
      this.checkExcessivePermissions(parsed, lines, issues);

      // 3. AD103: Insecure pull_request_target
      this.checkPullRequestTarget(parsed, lines, issues);

      // 4. AD104: Script Injection in Run Commands
      this.checkScriptInjection(parsed, lines, issues);

      // 5. AD105: Plaintext Secrets in Run Commands
      this.checkSecrets(lines, issues);

      // 6. AD201 & AD202 & AD203: Supply Chain & Pinning
      this.checkSupplyChain(lines, issues);

      // 7. AD301 & AD303: Runners Compatibility
      this.checkRunners(lines, issues);

      // 8. AD401: Missing Job Timeout
      this.checkTimeouts(parsed, lines, issues);

      // 9. AD402: Missing Step Names
      this.checkStepNames(parsed, lines, issues);

      // 10. AD403: Missing Fail Fast
      this.checkFailFast(parsed, lines, issues);

      // 11. AD404: Missing Concurrency
      this.checkConcurrency(parsed, lines, issues);

      // Calculate security score and metrics
      const stats = this.computeStats(issues, parsed, lines);
      const score = this.computeScore(issues);

      return {
        isValidYaml: !parseResult.error,
        score: score.numeric,
        grade: score.grade,
        ratingLabel: score.label,
        issues: issues.sort((a, b) => a.line - b.line),
        stats,
        summary: {
          total: issues.length,
          critical: issues.filter(i => i.severity === Severity.CRITICAL).length,
          error: issues.filter(i => i.severity === Severity.ERROR).length,
          warning: issues.filter(i => i.severity === Severity.WARNING).length,
          info: issues.filter(i => i.severity === Severity.INFO).length
        }
      };
    }

    // Check AD101: Missing Permissions
    checkMissingPermissions(parsed, lines, issues) {
      if (!parsed || typeof parsed !== 'object') return;

      const hasTopLevelPerms = Object.prototype.hasOwnProperty.call(parsed, 'permissions');
      const jobs = parsed.jobs;

      if (!hasTopLevelPerms && jobs && typeof jobs === 'object') {
        const jobsWithoutPerms = [];
        for (const [jobId, job] of Object.entries(jobs)) {
          if (job && typeof job === 'object' && !Object.prototype.hasOwnProperty.call(job, 'permissions')) {
            jobsWithoutPerms.push(jobId);
          }
        }

        if (jobsWithoutPerms.length > 0) {
          const permLine = this.findKeyLine(lines, 'jobs') || 1;
          issues.push({
            id: 'AD101',
            name: 'missing-permissions',
            category: Category.SECURITY,
            severity: Severity.ERROR,
            line: permLine,
            message: `Missing explicit 'permissions' block at top level or in jobs: [${jobsWithoutPerms.join(', ')}]. By default, GitHub Actions may grant unrestricted read/write repository access.`,
            recommendation: 'Declare explicit minimal permissions at the workflow root, or individually per job.',
            remediation: 'permissions:\n  contents: read'
          });
        }
      }
    }

    // Check AD102: Excessive Permissions
    checkExcessivePermissions(parsed, lines, issues) {
      if (!parsed || typeof parsed !== 'object') return;

      const checkPermValue = (permVal, lineNum, context) => {
        if (typeof permVal === 'string' && permVal.trim() === 'write-all') {
          issues.push({
            id: 'AD102',
            name: 'excessive-permissions',
            category: Category.SECURITY,
            severity: Severity.CRITICAL,
            line: lineNum,
            message: `${context} specifies 'write-all' permissions. This violates the principle of least privilege.`,
            recommendation: 'Enumerate only the required scopes with granular permissions (e.g., contents: read).',
            remediation: 'permissions:\n  contents: read'
          });
        } else if (permVal && typeof permVal === 'object') {
          if (permVal.contents === 'write' && (parsed.on === 'pull_request' || (parsed.on && parsed.on.pull_request))) {
            issues.push({
              id: 'AD102',
              name: 'excessive-permissions',
              category: Category.SECURITY,
              severity: Severity.WARNING,
              line: lineNum,
              message: `${context} grants 'contents: write' on pull_request trigger. PR workflows rarely require repository write access.`,
              recommendation: 'Downgrade to contents: read unless this workflow creates commits or releases.',
              remediation: 'contents: read'
            });
          }
        }
      };

      if (parsed.permissions) {
        const line = this.findKeyLine(lines, 'permissions') || 1;
        checkPermValue(parsed.permissions, line, 'Top-level permissions');
      }

      if (parsed.jobs && typeof parsed.jobs === 'object') {
        for (const [jobId, job] of Object.entries(parsed.jobs)) {
          if (job && job.permissions) {
            const line = this.findJobKeyLine(lines, jobId, 'permissions');
            checkPermValue(job.permissions, line, `Job '${jobId}' permissions`);
          }
        }
      }
    }

    // Check AD103: Insecure pull_request_target
    checkPullRequestTarget(parsed, lines, issues) {
      if (!parsed || typeof parsed !== 'object') return;

      const onVal = parsed.on;
      const isPRTarget = onVal === 'pull_request_target' ||
        (typeof onVal === 'object' && onVal !== null && Object.prototype.hasOwnProperty.call(onVal, 'pull_request_target'));

      if (!isPRTarget) return;

      // Look for checkout step with untrusted ref
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}/i.test(line) ||
            /ref\s*:\s*\$\{\{\s*github\.head_ref\s*\}\}/i.test(line)) {
          issues.push({
            id: 'AD103',
            name: 'insecure-pull-request-target',
            category: Category.SECURITY,
            severity: Severity.CRITICAL,
            line: i + 1,
            message: "Insecure 'pull_request_target' trigger combined with checking out untrusted PR head commit. This allows untrusted code to run with elevated write tokens and secrets.",
            recommendation: "Switch trigger to standard 'pull_request', or avoid checking out untrusted PR code in privileged workflows.",
            remediation: "on:\n  pull_request:\n    branches: [main]"
          });
          break;
        }
      }
    }

    // Check AD104: Script Injection
    checkScriptInjection(parsed, lines, issues) {
      let inRunBlock = false;
      let runIndent = 0;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const runMatch = line.match(/^(\s*)(?:-\s*)?run\s*:\s*(.*)$/);

        if (runMatch) {
          runIndent = runMatch[1].length;
          const inlineCmd = runMatch[2].trim();
          inRunBlock = inlineCmd === '|' || inlineCmd === '>';

          // Check inline run commands
          if (!inRunBlock && inlineCmd.length > 0) {
            this.inspectScriptLine(inlineCmd, i + 1, issues);
          }
        } else if (inRunBlock) {
          const currentIndent = line.search(/\S/);
          if (currentIndent <= runIndent && line.trim().length > 0) {
            inRunBlock = false;
          } else {
            this.inspectScriptLine(line, i + 1, issues);
          }
        }
      }
    }

    inspectScriptLine(lineText, lineNum, issues) {
      for (const item of UNTRUSTED_CONTEXT_PATTERNS) {
        if (item.pattern.test(lineText)) {
          issues.push({
            id: 'AD104',
            name: 'script-injection',
            category: Category.SECURITY,
            severity: Severity.CRITICAL,
            line: lineNum,
            message: `Potential command injection vulnerability! Untrusted GitHub context '${item.name}' is directly interpolated in a shell command.`,
            recommendation: `Pass the context value via the step's 'env:' block, and refer to it as an environment variable ($VAR) in the run script.`,
            remediation: `env:\n  SAFE_INPUT: \${{ ${item.name} }}\nrun: |\n  echo "Processing: $SAFE_INPUT"`
          });
        }
      }
    }

    // Check AD105: Plaintext Secrets
    checkSecrets(lines, issues) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*#/.test(line)) continue; // ignore comments

        for (const sec of SECRET_PATTERNS) {
          if (sec.pattern.test(line)) {
            issues.push({
              id: 'AD105',
              name: 'plaintext-secret-in-run',
              category: Category.SECURITY,
              severity: Severity.CRITICAL,
              line: i + 1,
              message: `High risk: Detected hardcoded credential or token matching pattern for '${sec.name}'.`,
              recommendation: 'Store credentials in repository or organization secrets and reference via ${{ secrets.NAME }}.',
              remediation: 'env:\n  API_TOKEN: ${{ secrets.MY_SERVICE_TOKEN }}'
            });
          }
        }
      }
    }

    // Check AD201, AD202, AD203: Supply Chain Pinning
    checkSupplyChain(lines, issues) {
      const usesRegex = /^\s*(?:-\s*)?uses\s*:\s*([^#\r\n]+?)(?:\s*#\s*(.*))?$/;
      const shaRegex = /^[0-9a-fA-F]{40}$/;

      for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(usesRegex);
        if (!match) continue;

        const actionFull = match[1].trim().replace(/^['"]|['"]$/g, '');
        const comment = (match[2] || '').trim();

        // Local actions like ./ or docker:// are exempted
        if (actionFull.startsWith('./') || actionFull.startsWith('docker://')) {
          continue;
        }

        const parts = actionFull.split('@');
        const actionPath = parts[0];
        const ref = parts[1] || '';

        // AD203: Check deprecated action version
        if (DEPRECATED_ACTIONS[actionFull]) {
          issues.push({
            id: 'AD203',
            name: 'deprecated-action-version',
            category: Category.SUPPLY_CHAIN,
            severity: Severity.WARNING,
            line: i + 1,
            message: `Outdated action version '${actionFull}'. ${DEPRECATED_ACTIONS[actionFull]}.`,
            recommendation: 'Upgrade to the current supported major action version and pin to commit SHA.',
            remediation: KNOWN_ACTION_PINS[actionFull] ?
              `uses: ${actionPath}@${KNOWN_ACTION_PINS[actionFull].sha} # ${KNOWN_ACTION_PINS[actionFull].tag}` : null
          });
        }

        // AD202: Check mutable branch ref
        if (MUTABLE_BRANCHES.has(ref.toLowerCase())) {
          issues.push({
            id: 'AD202',
            name: 'mutable-branch-ref',
            category: Category.SUPPLY_CHAIN,
            severity: Severity.ERROR,
            line: i + 1,
            message: `Action '${actionFull}' references mutable branch '@${ref}'. Upstream branch changes can compromise pipeline integrity without notice.`,
            recommendation: 'Pin the action to an immutable 40-character commit SHA.',
            remediation: `uses: ${actionPath}@<commit-sha> # ${ref}`
          });
          continue;
        }

        // AD201: Check unpinned SHA
        if (!shaRegex.test(ref)) {
          const knownPin = KNOWN_ACTION_PINS[actionFull];
          const fixSnippet = knownPin ?
            `uses: ${actionPath}@${knownPin.sha} # ${knownPin.tag}` :
            `uses: ${actionPath}@<40-char-commit-sha> # ${ref}`;

          issues.push({
            id: 'AD201',
            name: 'unpinned-action-sha',
            category: Category.SUPPLY_CHAIN,
            severity: Severity.WARNING,
            line: i + 1,
            message: `Action '${actionFull}' is not pinned to a full 40-character commit SHA. Tags can be reassigned or hijacked.`,
            recommendation: 'Pin the action to an immutable commit hash to defend against supply-chain attacks.',
            remediation: fixSnippet
          });
        }
      }
    }

    // Check AD301: Deprecated Runners
    checkRunners(lines, issues) {
      const runsOnRegex = /^\s*runs-on\s*:\s*([^#\r\n]+)/;

      for (let i = 0; i < lines.length; i++) {
        const match = lines[i].match(runsOnRegex);
        if (!match) continue;

        const runnerVal = match[1].trim().replace(/^['"]|['"]$/g, '');

        if (DEPRECATED_RUNNERS[runnerVal]) {
          const info = DEPRECATED_RUNNERS[runnerVal];
          issues.push({
            id: 'AD301',
            name: 'deprecated-runner',
            category: Category.RUNNERS,
            severity: Severity.ERROR,
            line: i + 1,
            message: `Deprecated runner '${runnerVal}'. Retired by GitHub (${info.retirement}). Builds on this runner may fail or receive no security updates.`,
            recommendation: `Migrate to '${info.replacement}'.`,
            remediation: `runs-on: ubuntu-latest`
          });
        }
      }
    }

    // Check AD401: Missing Job Timeouts
    checkTimeouts(parsed, lines, issues) {
      if (!parsed || !parsed.jobs || typeof parsed.jobs !== 'object') return;

      for (const [jobId, job] of Object.entries(parsed.jobs)) {
        if (job && typeof job === 'object' && !Object.prototype.hasOwnProperty.call(job, 'timeout-minutes')) {
          const line = this.findJobLine(lines, jobId);
          issues.push({
            id: 'AD401',
            name: 'missing-job-timeout',
            category: Category.BEST_PRACTICE,
            severity: Severity.WARNING,
            line: line,
            message: `Job '${jobId}' does not define 'timeout-minutes'. If a step hangs, the runner can consume up to 360 minutes (6 hours) of pipeline quota.`,
            recommendation: 'Specify a reasonable timeout (e.g. timeout-minutes: 15).',
            remediation: 'timeout-minutes: 15'
          });
        }
      }
    }

    // Check AD402: Missing Step Names
    checkStepNames(parsed, lines, issues) {
      if (!parsed || !parsed.jobs || typeof parsed.jobs !== 'object') return;

      for (const [jobId, job] of Object.entries(parsed.jobs)) {
        if (!job || !Array.isArray(job.steps)) continue;

        job.steps.forEach((step, idx) => {
          if (step && typeof step === 'object' && !step.name) {
            // Flag if it's a multi-line run or action
            const isComplex = (step.run && step.run.includes('\n')) || step.uses;
            if (isComplex) {
              const line = this.findStepLine(lines, jobId, idx + 1);
              issues.push({
                id: 'AD402',
                name: 'missing-step-name',
                category: Category.BEST_PRACTICE,
                severity: Severity.INFO,
                line: line,
                message: `Step #${idx + 1} in job '${jobId}' lacks an explicit 'name:' description.`,
                recommendation: 'Add a descriptive step name to clarify execution logs and debugging.',
                remediation: `name: "Run step #${idx + 1}"`
              });
            }
          }
        });
      }
    }

    // Check AD403: Missing Fail Fast
    checkFailFast(parsed, lines, issues) {
      if (!parsed || !parsed.jobs || typeof parsed.jobs !== 'object') return;

      for (const [jobId, job] of Object.entries(parsed.jobs)) {
        if (job && job.strategy && job.strategy.matrix) {
          if (!Object.prototype.hasOwnProperty.call(job.strategy, 'fail-fast')) {
            const line = this.findJobKeyLine(lines, jobId, 'strategy');
            issues.push({
              id: 'AD403',
              name: 'missing-fail-fast',
              category: Category.BEST_PRACTICE,
              severity: Severity.INFO,
              line: line,
              message: `Matrix in job '${jobId}' does not explicitly declare 'fail-fast'. Default is 'true', terminating sibling matrix jobs on first failure.`,
              recommendation: 'Explicitly specify fail-fast: false if you want full matrix results regardless of isolated failures.',
              remediation: 'strategy:\n  fail-fast: false'
            });
          }
        }
      }
    }

    // Check AD404: Missing Concurrency
    checkConcurrency(parsed, lines, issues) {
      if (!parsed || typeof parsed !== 'object') return;

      const hasConcurrency = Object.prototype.hasOwnProperty.call(parsed, 'concurrency');
      const triggers = parsed.on;

      const isPushOrPR = triggers === 'push' || triggers === 'pull_request' ||
        (triggers && (triggers.push || triggers.pull_request));

      if (isPushOrPR && !hasConcurrency) {
        issues.push({
          id: 'AD404',
          name: 'missing-concurrency',
          category: Category.BEST_PRACTICE,
          severity: Severity.INFO,
          line: 1,
          message: "Workflow triggers on push/PR but has no 'concurrency' group configured. Rapid commits will queue redundant concurrent builds.",
          recommendation: "Add a concurrency group with 'cancel-in-progress: true' to save runner minutes.",
          remediation: "concurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: true"
        });
      }
    }

    // Helpers to find line numbers in YAML
    findKeyLine(lines, key) {
      const regex = new RegExp(`^\\s*${key}\\s*:`);
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) return i + 1;
      }
      return 1;
    }

    findJobLine(lines, jobId) {
      const regex = new RegExp(`^\\s{2,4}${jobId}\\s*:`);
      for (let i = 0; i < lines.length; i++) {
        if (regex.test(lines[i])) return i + 1;
      }
      return 1;
    }

    findJobKeyLine(lines, jobId, key) {
      let inTargetJob = false;
      const jobRegex = new RegExp(`^\\s{2,4}${jobId}\\s*:`);
      const keyRegex = new RegExp(`^\\s{4,8}${key}\\s*:`);

      for (let i = 0; i < lines.length; i++) {
        if (jobRegex.test(lines[i])) {
          inTargetJob = true;
          continue;
        }
        if (inTargetJob) {
          if (keyRegex.test(lines[i])) return i + 1;
          if (/^\s{2,4}[a-zA-Z0-9_-]+\s*:/.test(lines[i])) {
            break;
          }
        }
      }
      return 1;
    }

    findStepLine(lines, jobId, stepIndex) {
      let inJob = false;
      let stepCount = 0;

      for (let i = 0; i < lines.length; i++) {
        if (new RegExp(`^\\s{2,4}${jobId}\\s*:`).test(lines[i])) {
          inJob = true;
          continue;
        }
        if (inJob) {
          if (/^\s*-\s*(?:name|uses|run)\s*:/.test(lines[i])) {
            stepCount++;
            if (stepCount === stepIndex) return i + 1;
          }
          if (/^\s{2,4}[a-zA-Z0-9_-]+\s*:/.test(lines[i]) && !lines[i].includes('steps:')) {
            break;
          }
        }
      }
      return 1;
    }

    computeStats(issues, parsed, lines) {
      const usesLines = lines.filter(l => /^\s*(?:-\s*)?uses\s*:/.test(l));
      const totalActions = usesLines.length;
      const shaRegex = /uses\s*:\s*[^@\s]+@[0-9a-fA-F]{40}/;
      const pinnedActions = usesLines.filter(l => shaRegex.test(l)).length;

      const hasPermissions = parsed && (parsed.permissions !== undefined);
      const hasConcurrency = parsed && (parsed.concurrency !== undefined);

      return {
        lineCount: lines.length,
        jobCount: parsed && parsed.jobs ? Object.keys(parsed.jobs).length : 0,
        actionCount: totalActions,
        pinnedActionCount: pinnedActions,
        pinningRatio: totalActions > 0 ? Math.round((pinnedActions / totalActions) * 100) : 100,
        hasExplicitPermissions: Boolean(hasPermissions),
        hasConcurrency: Boolean(hasConcurrency)
      };
    }

    computeScore(issues) {
      let penalty = 0;
      for (const issue of issues) {
        if (issue.severity === Severity.CRITICAL) penalty += 25;
        else if (issue.severity === Severity.ERROR) penalty += 15;
        else if (issue.severity === Severity.WARNING) penalty += 8;
        else if (issue.severity === Severity.INFO) penalty += 2;
      }

      const score = Math.max(0, 100 - penalty);
      let grade = 'A+';
      let label = 'Hardened Security Posture';

      if (score >= 90) {
        grade = 'A+';
        label = 'Hardened Security Posture';
      } else if (score >= 80) {
        grade = 'A';
        label = 'Strong Workflow Security';
      } else if (score >= 70) {
        grade = 'B';
        label = 'Acceptable — Minor Warnings';
      } else if (score >= 60) {
        grade = 'C';
        label = 'Needs Attention — Security Debt';
      } else if (score >= 40) {
        grade = 'D';
        label = 'High Risk Security Posture';
      } else {
        grade = 'F';
        label = 'Critical Exploits Detected';
      }

      return { numeric: score, grade, label };
    }
  }

  // Sample Workflow Presets
  const Presets = {
    VULNERABLE: `name: Pull Request Auditor & Notification

on:
  pull_request_target:
    branches: [main]

jobs:
  triage:
    runs-on: ubuntu-18.04
    steps:
      - name: Check out untrusted pull request branch
        uses: actions/checkout@v2
        with:
          ref: \${{ github.event.pull_request.head.sha }}

      - name: Setup Node environment
        uses: actions/setup-node@main
        with:
          node-version: 16

      - name: Process Issue or PR Title
        run: |
          echo "Processing PR from \${{ github.head_ref }}"
          node -e "console.log('Title: ' + '\${{ github.event.issue.title }}')"
          npm test

      - name: Publish Build Notification
        run: |
          curl -H "Authorization: token ghp_999999999999999999999999999999999999" \\
            -X POST https://api.github.com/repos/example/notify
`,

    CICD_PIPELINE: `name: Build & Test CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build:
    name: Test Application
    runs-on: ubuntu-20.04
    strategy:
      matrix:
        node: [18, 20]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: \${{ matrix.node }}
          cache: 'npm'

      - run: |
          npm ci
          npm test
          npm run build
`,

    HARDENED: `name: Production CI/CD Pipeline

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read

concurrency:
  group: \${{ github.workflow }}-\${{ github.ref }}
  cancel-in-progress: true

jobs:
  test:
    name: Lint, Test & Validate
    runs-on: ubuntu-latest
    timeout-minutes: 15
    strategy:
      fail-fast: false
      matrix:
        node-version: ["20", "22"]

    steps:
      - name: Check out source repository
        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false

      - name: Set up Node.js \${{ matrix.node-version }}
        uses: actions/setup-node@1e60f620b9541d16abce94cb522027ec595dacd5 # v4.2.0
        with:
          node-version: \${{ matrix.node-version }}
          cache: 'npm'

      - name: Install dependencies cleanly
        run: npm ci

      - name: Execute test suite
        run: npm test
`
  };

  // Export globally
  global.ActionAuditor = ActionAuditor;
  global.ActionAuditorPresets = Presets;

})(typeof window !== 'undefined' ? window : this);
