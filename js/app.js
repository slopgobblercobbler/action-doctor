/**
 * Action Doctor UI Application Logic
 */

(function () {
  'use strict';

  const auditor = new ActionAuditor();

  // Elements
  const editor = document.getElementById('yaml-editor');
  const lineNumbers = document.getElementById('line-numbers');
  const editorStats = document.getElementById('editor-stats');
  const findingsContainer = document.getElementById('findings-container');
  const dropZone = document.getElementById('editor-drop-zone');
  const fileUpload = document.getElementById('file-upload');
  const toast = document.getElementById('toast-notice');

  // Score Elements
  const scoreValue = document.getElementById('score-value');
  const scoreGrade = document.getElementById('score-grade');
  const scoreCircle = document.getElementById('score-circle');
  const scoreTitle = document.getElementById('score-title');
  const scoreDescription = document.getElementById('score-description');

  // Metrics Elements
  const metricPinning = document.getElementById('metric-pinning');
  const metricPinningBadge = document.getElementById('metric-pinning-badge');
  const metricPermissions = document.getElementById('metric-permissions');
  const metricPermissionsBadge = document.getElementById('metric-permissions-badge');
  const metricRunners = document.getElementById('metric-runners');
  const metricRunnersBadge = document.getElementById('metric-runners-badge');
  const metricTimeouts = document.getElementById('metric-timeouts');
  const metricTimeoutsBadge = document.getElementById('metric-timeouts-badge');

  // Counts
  const countAll = document.getElementById('count-all');
  const countCritical = document.getElementById('count-critical');
  const countError = document.getElementById('count-error');
  const countWarning = document.getElementById('count-warning');
  const countInfo = document.getElementById('count-info');

  let currentAuditResult = null;
  let activeFilter = 'all';
  let debounceTimer = null;

  // Initialize
  function init() {
    setupEventListeners();
    loadPreset('VULNERABLE');
  }

  function setupEventListeners() {
    // Editor typing & scrolling
    editor.addEventListener('input', () => {
      updateLineNumbers();
      updateEditorStats();
      triggerAuditDebounced();
    });

    editor.addEventListener('scroll', () => {
      lineNumbers.scrollTop = editor.scrollTop;
    });

    // Preset buttons
    document.querySelectorAll('.btn-preset').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.btn-preset').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const presetKey = btn.dataset.preset;
        loadPreset(presetKey);
      });
    });

    // Filter pills
    document.querySelectorAll('.filter-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        activeFilter = pill.dataset.filter;
        renderFindings();
      });
    });

    // Clear Button
    document.getElementById('btn-clear').addEventListener('click', () => {
      editor.value = '';
      updateLineNumbers();
      updateEditorStats();
      runAudit();
      showToast('Editor cleared');
    });

    // Copy YAML
    document.getElementById('btn-copy-yaml').addEventListener('click', () => {
      if (!editor.value.trim()) return;
      navigator.clipboard.writeText(editor.value).then(() => {
        showToast('YAML copied to clipboard!');
      });
    });

    // Export Markdown Report
    document.getElementById('btn-export-markdown').addEventListener('click', () => {
      exportMarkdownReport();
    });

    // File Upload via picker
    fileUpload.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) readFile(file);
    });

    // Drag and Drop
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
      e.preventDefault();
      e.stopPropagation();
    }

    dropZone.addEventListener('dragover', () => {
      dropZone.style.boxShadow = 'inset 0 0 0 2px var(--border-highlight)';
    });

    dropZone.addEventListener('dragleave', () => {
      dropZone.style.boxShadow = 'none';
    });

    dropZone.addEventListener('drop', (e) => {
      dropZone.style.boxShadow = 'none';
      const dt = e.dataTransfer;
      const file = dt.files[0];
      if (file) readFile(file);
    });
  }

  function readFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      editor.value = e.target.result;
      updateLineNumbers();
      updateEditorStats();
      runAudit();
      showToast(`Loaded: ${file.name}`);
      document.querySelectorAll('.btn-preset').forEach(b => b.classList.remove('active'));
    };
    reader.readAsText(file);
  }

  function loadPreset(key) {
    if (ActionAuditorPresets[key]) {
      editor.value = ActionAuditorPresets[key].trim();
      updateLineNumbers();
      updateEditorStats();
      runAudit();
    }
  }

  function updateLineNumbers() {
    const lines = editor.value.split('\n').length;
    let numbersHtml = '';
    for (let i = 1; i <= Math.max(1, lines); i++) {
      numbersHtml += `${i}\n`;
    }
    lineNumbers.textContent = numbersHtml;
  }

  function updateEditorStats() {
    const text = editor.value;
    const lines = text.length > 0 ? text.split('\n').length : 0;
    const chars = text.length;
    editorStats.textContent = `Lines: ${lines} · Chars: ${chars}`;
  }

  function triggerAuditDebounced() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      runAudit();
    }, 250);
  }

  function runAudit() {
    const yamlContent = editor.value;
    currentAuditResult = auditor.audit(yamlContent);

    updateScoreDisplay(currentAuditResult);
    updateMetrics(currentAuditResult);
    updateFilterCounts(currentAuditResult);
    renderFindings();
  }

  function updateScoreDisplay(result) {
    const score = result.score;
    const grade = result.grade;
    scoreValue.textContent = score;
    scoreGrade.textContent = grade;

    let scoreColor = '#3fb950'; // green
    if (score < 40) scoreColor = '#f85149'; // red
    else if (score < 60) scoreColor = '#f0883e'; // orange
    else if (score < 80) scoreColor = '#d29922'; // yellow
    else if (score < 90) scoreColor = '#58a6ff'; // blue

    scoreCircle.style.setProperty('--score-pct', score);
    scoreCircle.style.setProperty('--score-color', scoreColor);

    scoreTitle.textContent = `${grade} — ${result.ratingLabel}`;
    scoreDescription.textContent = score === 100 ?
      'All security and hygiene checks passed. Outstanding CI/CD posture!' :
      `Identified ${result.summary.total} potential improvements across permissions, supply-chain, and runners.`;
  }

  function updateMetrics(result) {
    const stats = result.stats;

    // Supply Chain Pinning
    metricPinning.textContent = `${stats.pinningRatio}%`;
    if (stats.pinningRatio === 100) {
      metricPinningBadge.textContent = 'Fully Pinned';
      metricPinningBadge.style.background = 'rgba(63, 185, 80, 0.15)';
      metricPinningBadge.style.color = '#3fb950';
    } else {
      metricPinningBadge.textContent = `${stats.pinnedActionCount}/${stats.actionCount} Pinned`;
      metricPinningBadge.style.background = 'rgba(210, 153, 34, 0.15)';
      metricPinningBadge.style.color = '#d29922';
    }

    // Permissions
    if (stats.hasExplicitPermissions) {
      metricPermissions.textContent = 'Explicit';
      metricPermissionsBadge.textContent = 'Least Privilege';
      metricPermissionsBadge.style.background = 'rgba(63, 185, 80, 0.15)';
      metricPermissionsBadge.style.color = '#3fb950';
    } else {
      metricPermissions.textContent = 'Default';
      metricPermissionsBadge.textContent = 'Missing Block';
      metricPermissionsBadge.style.background = 'rgba(248, 81, 73, 0.15)';
      metricPermissionsBadge.style.color = '#f85149';
    }

    // Runners
    const hasDeprecatedRunners = result.issues.some(i => i.id === 'AD301');
    if (hasDeprecatedRunners) {
      metricRunners.textContent = 'Deprecated';
      metricRunnersBadge.textContent = 'Upgrade Required';
      metricRunnersBadge.style.background = 'rgba(248, 81, 73, 0.15)';
      metricRunnersBadge.style.color = '#f85149';
    } else {
      metricRunners.textContent = 'Supported';
      metricRunnersBadge.textContent = 'Modern';
      metricRunnersBadge.style.background = 'rgba(63, 185, 80, 0.15)';
      metricRunnersBadge.style.color = '#3fb950';
    }

    // Timeouts
    const hasMissingTimeouts = result.issues.some(i => i.id === 'AD401');
    if (hasMissingTimeouts) {
      metricTimeouts.textContent = 'Unbounded';
      metricTimeoutsBadge.textContent = '6h Max Risk';
      metricTimeoutsBadge.style.background = 'rgba(210, 153, 34, 0.15)';
      metricTimeoutsBadge.style.color = '#d29922';
    } else {
      metricTimeouts.textContent = 'Bounded';
      metricTimeoutsBadge.textContent = 'Protected';
      metricTimeoutsBadge.style.background = 'rgba(63, 185, 80, 0.15)';
      metricTimeoutsBadge.style.color = '#3fb950';
    }
  }

  function updateFilterCounts(result) {
    countAll.textContent = result.summary.total;
    countCritical.textContent = result.summary.critical;
    countError.textContent = result.summary.error;
    countWarning.textContent = result.summary.warning;
    countInfo.textContent = result.summary.info;
  }

  function renderFindings() {
    findingsContainer.innerHTML = '';

    if (!currentAuditResult) return;

    let filtered = currentAuditResult.issues;
    if (activeFilter !== 'all') {
      filtered = filtered.filter(i => i.severity === activeFilter);
    }

    if (filtered.length === 0) {
      if (currentAuditResult.issues.length === 0) {
        findingsContainer.innerHTML = `
          <div class="clean-posture-card">
            <div class="clean-icon">✓</div>
            <div class="clean-title">Zero Security or Hygiene Findings</div>
            <div class="clean-text">
              This GitHub Actions workflow demonstrates excellent security hygiene: pinned commit SHAs, explicit minimal permissions, bounded timeouts, and modern runner targets.
            </div>
          </div>
        `;
      } else {
        findingsContainer.innerHTML = `
          <div style="text-align: center; color: var(--text-muted); padding: 2.5rem 1rem;">
            No issues match the selected filter '${activeFilter}'.
          </div>
        `;
      }
      return;
    }

    filtered.forEach(issue => {
      const card = document.createElement('div');
      card.className = `finding-card ${issue.severity}`;

      let remediationHtml = '';
      if (issue.remediation) {
        remediationHtml = `
          <div class="remediation-block">
            <code class="remediation-code">${escapeHtml(issue.remediation)}</code>
            <button class="copy-snippet-btn" data-snippet="${escapeAttr(issue.remediation)}">Copy Fix</button>
          </div>
        `;
      }

      card.innerHTML = `
        <div class="finding-header">
          <div class="finding-tags">
            <span class="badge-id">${issue.id}</span>
            <span class="badge-severity ${issue.severity}">${issue.severity}</span>
            <span class="badge-category">${issue.category}</span>
          </div>
          <button class="badge-line" data-line="${issue.line}" title="Jump to line ${issue.line}">
            Line ${issue.line}
          </button>
        </div>
        <div class="finding-message">${escapeHtml(issue.message)}</div>
        <div class="finding-recommendation"><strong>Recommendation:</strong> ${escapeHtml(issue.recommendation)}</div>
        ${remediationHtml}
      `;

      findingsContainer.appendChild(card);
    });

    // Attach click events to line badges
    findingsContainer.querySelectorAll('.badge-line').forEach(btn => {
      btn.addEventListener('click', () => {
        const line = parseInt(btn.dataset.line, 10);
        highlightEditorLine(line);
      });
    });

    // Attach copy fix snippet buttons
    findingsContainer.querySelectorAll('.copy-snippet-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const snippet = btn.dataset.snippet;
        navigator.clipboard.writeText(snippet).then(() => {
          showToast('Remediation snippet copied!');
        });
      });
    });
  }

  function highlightEditorLine(lineNumber) {
    const text = editor.value;
    const lines = text.split('\n');
    let charStart = 0;

    for (let i = 0; i < lineNumber - 1 && i < lines.length; i++) {
      charStart += lines[i].length + 1;
    }

    const lineLength = lines[lineNumber - 1] ? lines[lineNumber - 1].length : 0;
    const charEnd = charStart + lineLength;

    editor.focus();
    editor.setSelectionRange(charStart, charEnd);

    // Scroll roughly to line
    const approxLineHeight = 22;
    editor.scrollTop = Math.max(0, (lineNumber - 5) * approxLineHeight);
    lineNumbers.scrollTop = editor.scrollTop;
  }

  function exportMarkdownReport() {
    if (!currentAuditResult) return;

    const res = currentAuditResult;
    let md = `# Action Doctor — GitHub Actions Audit Report\n\n`;
    md += `**Date:** ${new Date().toUTCString()}\n`;
    md += `**Score:** ${res.score}% (${res.grade})\n`;
    md += `**Rating:** ${res.ratingLabel}\n\n`;

    md += `## Summary Metrics\n`;
    md += `- **Total Issues:** ${res.summary.total} (Critical: ${res.summary.critical}, Error: ${res.summary.error}, Warning: ${res.summary.warning}, Info: ${res.summary.info})\n`;
    md += `- **Actions Pinned:** ${res.stats.pinnedActionCount} / ${res.stats.actionCount} (${res.stats.pinningRatio}%)\n`;
    md += `- **Explicit Permissions:** ${res.stats.hasExplicitPermissions ? 'Yes' : 'No'}\n`;
    md += `- **Concurrency Protection:** ${res.stats.hasConcurrency ? 'Yes' : 'No'}\n\n`;

    md += `## Detailed Findings\n\n`;
    if (res.issues.length === 0) {
      md += `*No security or hygiene findings detected. 100% compliant!*\n`;
    } else {
      res.issues.forEach(i => {
        md += `### [${i.id}] ${i.name.toUpperCase()} (Line ${i.line}) — Severity: ${i.severity.toUpperCase()}\n`;
        md += `**Category:** ${i.category}\n\n`;
        md += `${i.message}\n\n`;
        md += `**Remediation Recommendation:**\n${i.recommendation}\n\n`;
        if (i.remediation) {
          md += `\`\`\`yaml\n${i.remediation}\n\`\`\`\n\n`;
        }
        md += `---\n\n`;
      });
    }

    md += `*Generated automatically in-browser by Action Doctor.*`;

    navigator.clipboard.writeText(md).then(() => {
      showToast('Markdown audit report copied to clipboard!');
    });
  }

  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.add('show');
    setTimeout(() => {
      toast.classList.remove('show');
    }, 2400);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, function (m) {
      return {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
      }[m];
    });
  }

  function escapeAttr(str) {
    if (!str) return '';
    return str.replace(/"/g, '&quot;');
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
