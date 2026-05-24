/**
 * @fileoverview CompliTrack — Main application controller.
 * Orchestrates auth, data loading, UI rendering, and realtime updates.
 */

import { supabase } from './js/config.js';
import { SEARCH_DEBOUNCE_MS } from './js/config.js';
import * as Auth from './js/auth.js';
import * as DB from './js/db.js';
import {
  formatDate, toInputDate, debounce, escapeHtml,
  statusBadge, statusClass, showToast, confirmDialog, skeletonRows,
} from './js/utils.js';

// ─── DOM references ──────────────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

const loginView = $('#loginView');
const systemView = $('#systemView');
const loginForm = $('#loginForm');
const logoutBtn = $('#logoutBtn');
const navButtons = $$('.nav-btn');
const panels = $$('.panel');
const breadcrumbCurrent = $('#breadcrumbCurrent');
const createReportBtn = $('#createReportBtn');
const goReportsBtn = $('[data-go-reports]');
const frameworkFilter = $('#frameworkFilter');
const complianceTableBody = $('#complianceTableBody');
const violationsBody = $('#violationsBody');
const trendBars = $('#trendBars');
const recentReportsBody = $('#recentReportsBody');
const notificationList = $('#notificationList');
const totalReportsMetric = $('#totalReportsMetric');
const pendingReportsMetric = $('#pendingReportsMetric');
const approvedReportsMetric = $('#approvedReportsMetric');
const rejectedReportsMetric = $('#rejectedReportsMetric');
const bubbleTotal = $('#bubbleTotal');
const bubblePending = $('#bubblePending');
const bubbleApproved = $('#bubbleApproved');
const bubbleRejected = $('#bubbleRejected');
const calendarGrid = $('#calendarGrid');
const calendarMonthLabel = $('#calendarMonthLabel');
const statusDonut = $('#statusDonut');
const statusDonutWrap = $('#statusDonutWrap');
const donutTotalLabel = $('#donutTotalLabel');
const reportSubmissionForm = $('#reportSubmissionForm');
const reportTitleInput = $('#reportTitleInput');
const reportDepartmentInput = $('#reportDepartmentInput');
const reportSummaryInput = $('#reportSummaryInput');
const reportFileInput = $('#reportFileInput');
const submissionStatus = $('#submissionStatus');
const reportStatus = $('#reportStatus');
const generatePrivacyBtn = $('#generatePrivacyReportBtn');
const generateCyberBtn = $('#generateCyberReportBtn');
const exportPdfBtn = $('#exportPdfBtn');
const exportExcelBtn = $('#exportExcelBtn');
const auditLogBody = $('#auditLogBody');
const auditTotalMetric = $('#auditTotalMetric');
const auditCriticalMetric = $('#auditCriticalMetric');
const auditSearchInput = $('#auditSearchInput');
const dashSearchInput = $('.search-input');
const documentTableBody = $('#documentTableBody');
const headerAlertDot = $('#headerAlertDot');
const loginError = $('#loginError');

const pageMeta = {
  dashboard: { breadcrumb: 'Dashboard' },
  'compliance-checker': { breadcrumb: 'Compliance' },
  'audit-log': { breadcrumb: 'Audit log' },
  reports: { breadcrumb: 'Reports' },
};

let _realtimeChannels = [];

// ════════════════════════════════════════════════════════════════
//  NAVIGATION
// ════════════════════════════════════════════════════════════════

function setActiveSection(targetId) {
  panels.forEach(p => p.classList.toggle('active', p.id === targetId));
  navButtons.forEach(b => b.classList.toggle('active', b.dataset.target === targetId));
  const meta = pageMeta[targetId];
  if (meta && breadcrumbCurrent) breadcrumbCurrent.textContent = meta.breadcrumb;
  if (meta) document.title = `${meta.breadcrumb} · CompliTrack`;

  // Lazy-load section data
  if (targetId === 'dashboard') loadDashboard();
  else if (targetId === 'compliance-checker') loadComplianceSection();
  else if (targetId === 'audit-log') loadAuditSection();
  else if (targetId === 'reports') loadReportsSection();
}

navButtons.forEach(b => b.addEventListener('click', () => setActiveSection(b.dataset.target)));
$$('.quick-nav').forEach(b => {
  if (b.dataset.target) b.addEventListener('click', () => setActiveSection(b.dataset.target));
});
if (createReportBtn) createReportBtn.addEventListener('click', () => setActiveSection('compliance-checker'));
if (goReportsBtn) goReportsBtn.addEventListener('click', () => setActiveSection('reports'));

// ════════════════════════════════════════════════════════════════
//  AUTHENTICATION
// ════════════════════════════════════════════════════════════════

let _mfaPendingFactorId = null; // tracks if we're in the MFA-verify step

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const emailEl = $('#login-user');
  const passEl = $('#login-pass');
  const mfaEl = $('#login-mfa');
  const btn = loginForm.querySelector('button[type="submit"]');
  const email = emailEl.value.trim();
  const pass = passEl.value;
  const mfaCode = mfaEl ? mfaEl.value.trim() : '';

  // ── Step 2: MFA verification ──────────────────────────────────

  if (_mfaPendingFactorId) {
    if (!mfaCode || mfaCode.length !== 6) {
      showToast('Please enter the 6-digit code from your authenticator app.', 'error');
      return;
    }
    btn.disabled = true;
    btn.textContent = 'Verifying MFA…';
    if (loginError) loginError.textContent = '';

    const { verified, error: mfaErr } = await Auth.verifyMfa(_mfaPendingFactorId, mfaCode);
    btn.disabled = false;

    if (mfaErr || !verified) {
      btn.textContent = 'Verify & sign in';
      if (loginError) loginError.textContent = mfaErr || 'Invalid code. Please try again.';
      showToast(mfaErr || 'Invalid MFA code.', 'error');
      return;
    }

    // MFA passed — complete login
    _mfaPendingFactorId = null;
    loginForm.classList.remove('mfa-step');
    btn.textContent = 'Sign in securely';
    const profile = Auth.getCurrentUser() || await Auth.restoreSession();
    enterSystem(profile);
    return;
  }

  // ── Step 1: Email / password ──────────────────────────────────
  if (!email || !pass) {
    showToast('Please enter email and password.', 'error');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Signing in…';
  if (loginError) loginError.textContent = '';

  const { user, error } = await Auth.signIn(email, pass);

  btn.disabled = false;
  btn.textContent = 'Sign in securely';

  if (error) {
    if (loginError) loginError.textContent = error;
    showToast(error, 'error');
    return;
  }

  // Check for enrolled MFA factors
  const { factors } = await Auth.getMfaFactors();

  if (factors.length > 0) {
    _mfaPendingFactorId = factors[0].id;

    // If the user already typed a 6-digit code, try verifying immediately!
    if (mfaCode && mfaCode.length === 6) {
      btn.textContent = 'Verifying MFA…';
      const { verified, error: mfaErr } = await Auth.verifyMfa(_mfaPendingFactorId, mfaCode);
      if (verified && !mfaErr) {
        _mfaPendingFactorId = null;
        btn.textContent = 'Sign in securely';
        enterSystem(Auth.getCurrentUser() || await Auth.restoreSession());
        return;
      }
      // If invalid, fall through to show the error and the MFA UI step
      showToast(mfaErr || 'Invalid MFA code.', 'error');
      if (loginError) loginError.textContent = mfaErr || 'Invalid code. Please try again.';
    } else {
      showToast('Enter the 6-digit code from your authenticator app.', 'info');
    }

    // Show step 2 UI (dims email/pass, highlights MFA input)
    loginForm.classList.add('mfa-step');
    btn.textContent = 'Verify & sign in';
    if (mfaEl) {
      mfaEl.focus();
      mfaEl.setAttribute('required', '');
    }
    return;
  }

  // No MFA — go straight in
  enterSystem(user);
});

logoutBtn.addEventListener('click', async () => {
  const ok = await confirmDialog('Sign out', 'Are you sure you want to log out?');
  if (!ok) return;
  await Auth.signOut();
  exitSystem();
});

function enterSystem(user) {
  loginView.classList.remove('active');
  systemView.classList.add('active');
  loginForm.reset();

  // Update user avatar
  const avatar = $('.user-avatar');
  if (avatar && user) avatar.textContent = (user.username || user.email || 'U')[0].toUpperCase();

  setActiveSection('dashboard');
  setupRealtime();
}

function exitSystem() {
  systemView.classList.remove('active');
  loginView.classList.add('active');
  loginForm.reset();
  teardownRealtime();
}

// Restore session on page load
(async () => {
  const user = await Auth.restoreSession();
  if (user) {
    enterSystem(user);
  }
})();

// ════════════════════════════════════════════════════════════════
//  DASHBOARD
// ════════════════════════════════════════════════════════════════

async function loadDashboard() {
  try {
    // Report stats
    const stats = await DB.getReportStats();
    if (totalReportsMetric) totalReportsMetric.textContent = stats.total;
    if (pendingReportsMetric) pendingReportsMetric.textContent = stats.pending + stats.underReview;
    if (approvedReportsMetric) approvedReportsMetric.textContent = stats.approved;
    if (rejectedReportsMetric) rejectedReportsMetric.textContent = stats.rejected;
    syncBubbleLegend();

    // Recent reports table
    if (recentReportsBody) {
      recentReportsBody.innerHTML = skeletonRows(4);
      const { data } = await DB.getReports({ page: 0 });
      renderRecentReports(data || []);
    }

    // Notifications
    const user = Auth.getCurrentUser();
    const notifs = await DB.getNotifications(user?.id);
    renderNotifications(notifs);

    // Unread count for badge
    const unread = await DB.getUnreadCount(user?.id);
    updateAlertBadge(unread);

  } catch (err) {
    showToast('Failed to load dashboard data.', 'error');
  }

  renderTrendBars();
  renderCalendar();
  refreshMfaStatus();
}

function renderRecentReports(reports) {
  if (!recentReportsBody) return;
  if (!reports.length) {
    recentReportsBody.innerHTML = '<tr><td colspan="4" class="muted" style="text-align:center;padding:2rem">No reports yet.</td></tr>';
    return;
  }
  recentReportsBody.innerHTML = reports.slice(0, 8).map(r => `
    <tr>
      <td>${escapeHtml(r.report_id)}</td>
      <td>${escapeHtml(r.department)}</td>
      <td>${statusBadge(r.status)}</td>
      <td>${formatDate(r.date_submitted)}</td>
    </tr>`).join('');
}

function renderNotifications(notifs) {
  if (!notificationList) return;
  if (!notifs || !notifs.length) {
    notificationList.innerHTML = '<li class="muted">No notifications.</li>';
    return;
  }
  notificationList.innerHTML = notifs.map(n => {
    const iconCls = n.type === 'critical' ? 'notif--critical' : n.type === 'warning' ? 'notif--warning' : 'notif--info';
    return `<li class="notif-item ${iconCls}${n.read ? ' notif--read' : ''}">${escapeHtml(n.message)}</li>`;
  }).join('');
}

function updateAlertBadge(count) {
  if (headerAlertDot) headerAlertDot.style.display = count > 0 ? '' : 'none';
  const dashBadge = $('[data-badge="dash"]');
  if (dashBadge) dashBadge.textContent = count || '';
}

const trendData = [68, 71, 73, 76, 78, 80, 82, 84, 83, 85, 86, 87];

function renderTrendBars() {
  if (!trendBars) return;
  trendBars.innerHTML = '';
  const maxVal = Math.max(...trendData);
  const peakIdx = trendData.indexOf(maxVal);
  trendData.forEach((value, idx) => {
    const bar = document.createElement('div');
    bar.className = `bar${idx === peakIdx ? ' is-peak' : ''}`;
    bar.style.height = `${Math.max(24, value * 1.8)}px`;
    bar.title = `Month ${idx + 1}: ${value}%`;
    trendBars.appendChild(bar);
  });
}

function syncBubbleLegend() {
  if (bubbleTotal) bubbleTotal.textContent = totalReportsMetric?.textContent || '0';
  if (bubblePending) bubblePending.textContent = pendingReportsMetric?.textContent || '0';
  if (bubbleApproved) bubbleApproved.textContent = approvedReportsMetric?.textContent || '0';
  if (bubbleRejected) bubbleRejected.textContent = rejectedReportsMetric?.textContent || '0';
  updateStatusDonut();
}

function updateStatusDonut() {
  if (!statusDonut) return;
  const pending = Number(pendingReportsMetric?.textContent) || 0;
  const approved = Number(approvedReportsMetric?.textContent) || 0;
  const rejected = Number(rejectedReportsMetric?.textContent) || 0;
  const sum = pending + approved + rejected;
  const total = Number(totalReportsMetric?.textContent) || sum;
  if (donutTotalLabel) donutTotalLabel.textContent = String(total);
  if (sum <= 0) {
    statusDonut.style.background = 'rgba(255,255,255,0.06)';
    return;
  }
  const pEnd = (pending / sum) * 100;
  const aEnd = pEnd + (approved / sum) * 100;
  statusDonut.style.background = `conic-gradient(#ff9f7a 0% ${pEnd}%, #4a5568 ${pEnd}% ${aEnd}%, #8b5a4a ${aEnd}% 100%)`;
}

function renderCalendar() {
  if (!calendarGrid) return;
  const now = new Date();
  const year = now.getFullYear();
  const month = now.getMonth();
  const monthNames = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  if (calendarMonthLabel) calendarMonthLabel.textContent = `${monthNames[month]} ${year}`;
  const firstDow = new Date(year, month, 1).getDay();
  const daysInMonth = new Date(year, month + 1, 0).getDate();
  const prevMonthDays = new Date(year, month, 0).getDate();
  const today = now.getDate();
  const eventDays = new Set([5, 7, 12, 18, 25]);
  const cells = [];
  for (let i = firstDow - 1; i >= 0; i--) cells.push(`<span class="calendar-day muted">${prevMonthDays - i}</span>`);
  for (let d = 1; d <= daysInMonth; d++) {
    let cls = 'calendar-day';
    if (d === today) cls += ' today';
    if (eventDays.has(d)) cls += ' has-event';
    cells.push(`<span class="${cls}">${d}</span>`);
  }
  const remainder = cells.length % 7;
  if (remainder) for (let d = 1; d <= 7 - remainder; d++) cells.push(`<span class="calendar-day muted">${d}</span>`);
  calendarGrid.innerHTML = cells.join('');
}

// ════════════════════════════════════════════════════════════════
//  MFA MANAGEMENT (Dashboard)
// ════════════════════════════════════════════════════════════════

const mfaStatusBadge = $('#mfaStatusBadge');
const mfaEnableBtn = $('#mfaEnableBtn');
const mfaDisableBtn = $('#mfaDisableBtn');
const mfaEnrollStep = $('#mfaEnrollStep');
const mfaQrWrap = $('#mfaQrWrap');
const mfaEnrollCode = $('#mfaEnrollCode');
const mfaVerifyBtn = $('#mfaVerifyBtn');
const mfaCancelBtn = $('#mfaCancelBtn');
const mfaEnrollError = $('#mfaEnrollError');
const mfaActions = $('#mfaActions');

let _enrollingFactorId = null;

/** Refresh the MFA card to reflect current enrolment state. */
async function refreshMfaStatus() {
  if (!mfaStatusBadge) return;
  const { factors } = await Auth.getMfaFactors();
  const isActive = factors.length > 0;

  mfaStatusBadge.className = `mfa-status-badge${isActive ? ' is-active' : ''}`;
  mfaStatusBadge.innerHTML = `<span class="status-dot${isActive ? ' status-dot--ok' : ''}"></span> ${isActive ? 'Active' : 'Disabled'}`;

  if (mfaEnableBtn) mfaEnableBtn.style.display = isActive ? 'none' : '';
  if (mfaDisableBtn) mfaDisableBtn.style.display = isActive ? '' : 'none';
  if (mfaEnrollStep) mfaEnrollStep.style.display = 'none';
  if (mfaActions) mfaActions.style.display = '';
  _enrollingFactorId = null;
}

// Enable → start enrolment
if (mfaEnableBtn) {
  mfaEnableBtn.addEventListener('click', async () => {
    mfaEnableBtn.disabled = true;
    mfaEnableBtn.textContent = 'Setting up…';
    if (mfaEnrollError) mfaEnrollError.textContent = '';

    const { factorId, qr, error } = await Auth.enrollMfa();
    mfaEnableBtn.disabled = false;
    mfaEnableBtn.textContent = 'Enable MFA';

    if (error) {
      showToast(error, 'error');
      return;
    }

    _enrollingFactorId = factorId;

    // Show QR
    if (mfaQrWrap) mfaQrWrap.innerHTML = `<img src="${qr}" alt="Scan this QR code with your authenticator app" />`;
    if (mfaActions) mfaActions.style.display = 'none';
    if (mfaEnrollStep) mfaEnrollStep.style.display = '';
    if (mfaEnrollCode) { mfaEnrollCode.value = ''; mfaEnrollCode.focus(); }
  });
}

// Verify enrolment code
if (mfaVerifyBtn) {
  mfaVerifyBtn.addEventListener('click', async () => {
    const code = mfaEnrollCode ? mfaEnrollCode.value.trim() : '';
    if (!code || code.length !== 6) {
      if (mfaEnrollError) mfaEnrollError.textContent = 'Enter the 6-digit code from your authenticator app.';
      return;
    }
    if (!_enrollingFactorId) {
      if (mfaEnrollError) mfaEnrollError.textContent = 'No pending factor. Please restart enrolment.';
      return;
    }

    mfaVerifyBtn.disabled = true;
    mfaVerifyBtn.textContent = 'Verifying…';

    const { verified, error } = await Auth.verifyMfa(_enrollingFactorId, code);

    mfaVerifyBtn.disabled = false;
    mfaVerifyBtn.textContent = 'Verify & activate';

    if (error || !verified) {
      if (mfaEnrollError) mfaEnrollError.textContent = error || 'Verification failed. Check the code and try again.';
      showToast(error || 'Verification failed.', 'error');
      return;
    }

    showToast('MFA enabled! Your account is now more secure.', 'success');
    await refreshMfaStatus();
  });
}

// Cancel enrolment
if (mfaCancelBtn) {
  mfaCancelBtn.addEventListener('click', async () => {
    // Unenroll the pending factor if we have one
    if (_enrollingFactorId) {
      await Auth.unenrollMfa(_enrollingFactorId);
    }
    _enrollingFactorId = null;
    if (mfaEnrollStep) mfaEnrollStep.style.display = 'none';
    if (mfaActions) mfaActions.style.display = '';
  });
}

// Disable MFA
if (mfaDisableBtn) {
  mfaDisableBtn.addEventListener('click', async () => {
    const ok = await confirmDialog('Disable MFA', 'This will remove two-factor authentication from your account. Continue?');
    if (!ok) return;

    mfaDisableBtn.disabled = true;
    mfaDisableBtn.textContent = 'Disabling…';

    const { factors } = await Auth.getMfaFactors();
    for (const f of factors) {
      await Auth.unenrollMfa(f.id);
    }

    mfaDisableBtn.disabled = false;
    mfaDisableBtn.textContent = 'Disable MFA';
    showToast('MFA has been disabled.', 'info');
    await refreshMfaStatus();
  });
}

// ════════════════════════════════════════════════════════════════
//  COMPLIANCE SECTION
// ════════════════════════════════════════════════════════════════

async function loadComplianceSection() {
  await Promise.all([loadComplianceControls(), loadViolations()]);
}

async function loadComplianceControls() {
  if (!complianceTableBody) return;
  complianceTableBody.innerHTML = skeletonRows(7);
  try {
    const fw = frameworkFilter ? frameworkFilter.value : 'ALL';
    const { data } = await DB.getControls({ frameworkCode: fw });
    renderComplianceTable(data || []);
  } catch (err) {
    complianceTableBody.innerHTML = '<tr><td colspan="7" class="muted" style="text-align:center">Failed to load controls.</td></tr>';
    showToast('Could not load compliance controls.', 'error');
  }
}

function renderComplianceTable(controls) {
  if (!complianceTableBody) return;
  if (!controls.length) {
    complianceTableBody.innerHTML = '<tr><td colspan="7" class="muted" style="text-align:center;padding:2rem">No controls found.</td></tr>';
    return;
  }
  complianceTableBody.innerHTML = controls.map(c => `
    <tr>
      <td>${escapeHtml(c.control_id)}</td>
      <td>${escapeHtml(c.compliance_frameworks?.code || '—')}</td>
      <td>${escapeHtml(c.requirement)}</td>
      <td>${statusBadge(c.status)}</td>
      <td>${escapeHtml(c.owner || '—')}</td>
      <td>${toInputDate(c.due_date)}</td>
      <td><button type="button" class="btn-review" data-control-id="${c.id}" data-control-label="${escapeHtml(c.control_id)}">Mark reviewed</button></td>
    </tr>`).join('');

  complianceTableBody.querySelectorAll('.btn-review').forEach(btn => {
    btn.addEventListener('click', async () => {
      const ok = await confirmDialog('Mark as reviewed', `Mark ${btn.dataset.controlLabel} as Compliant?`);
      if (!ok) return;
      try {
        btn.disabled = true;
        btn.textContent = 'Saving…';
        await DB.updateControlStatus(btn.dataset.controlId, 'Compliant');
        showToast(`${btn.dataset.controlLabel} marked as Compliant.`, 'success');
        await loadComplianceControls();
      } catch (err) {
        showToast(err.message, 'error');
        btn.disabled = false;
        btn.textContent = 'Mark reviewed';
      }
    });
  });
}

async function loadViolations() {
  if (!violationsBody) return;
  violationsBody.innerHTML = skeletonRows(5);
  try {
    const { data } = await DB.getViolations();
    renderViolationsTable(data || []);
  } catch (err) {
    violationsBody.innerHTML = '<tr><td colspan="5" class="muted" style="text-align:center">Failed to load violations.</td></tr>';
  }
}

function renderViolationsTable(violations) {
  if (!violationsBody) return;
  if (!violations.length) {
    violationsBody.innerHTML = '<tr><td colspan="5" class="muted" style="text-align:center;padding:2rem">No violations.</td></tr>';
    return;
  }
  violationsBody.innerHTML = violations.map(v => `
    <tr>
      <td>${escapeHtml(v.violation_id)}</td>
      <td>${escapeHtml(v.issue)}</td>
      <td><span class="tag tag--dark ${statusClass(v.severity) === 'danger' ? 'danger' : statusClass(v.severity) === 'warn' ? 'warn' : 'ok'}">${escapeHtml(v.severity)}</span></td>
      <td>${escapeHtml(v.corrective_action || '—')}</td>
      <td>${statusBadge(v.status)}</td>
    </tr>`).join('');
}

if (frameworkFilter) frameworkFilter.addEventListener('change', loadComplianceControls);

// ════════════════════════════════════════════════════════════════
//  REPORT SUBMISSION
// ════════════════════════════════════════════════════════════════

if (reportSubmissionForm) {
  reportSubmissionForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const title = reportTitleInput?.value.trim();
    const dept = reportDepartmentInput?.value.trim();
    const summary = reportSummaryInput?.value.trim();

    if (!title || !dept || !summary) {
      showToast('All fields are required.', 'error');
      return;
    }

    const btn = reportSubmissionForm.querySelector('button[type="submit"]');
    btn.disabled = true;
    btn.textContent = 'Submitting…';

    try {
      const user = Auth.getCurrentUser();
      const file = reportFileInput?.files[0];
      let fileUrl = null;

      // Upload file to Supabase Storage if present
      if (file) {
        const filePath = `reports/${Date.now()}_${file.name}`;
        const { error: uploadErr } = await supabase.storage.from('documents').upload(filePath, file);
        if (!uploadErr) {
          const { data: urlData } = supabase.storage.from('documents').getPublicUrl(filePath);
          fileUrl = urlData.publicUrl;
        }
      }

      const report = await DB.createReport({
        title, department: dept, summary,
        fileUrl, submittedBy: user?.id,
      });

      if (submissionStatus) {
        submissionStatus.textContent = `Report "${report.report_id}" submitted successfully.`;
        submissionStatus.className = 'status-msg status-msg--success';
      }
      showToast(`Report ${report.report_id} submitted!`, 'success');
      reportSubmissionForm.reset();
    } catch (err) {
      if (submissionStatus) {
        submissionStatus.textContent = `Error: ${err.message}`;
        submissionStatus.className = 'status-msg status-msg--error';
      }
      showToast(err.message, 'error');
    } finally {
      btn.disabled = false;
      btn.textContent = 'Submit compliance report';
    }
  });
}

// ════════════════════════════════════════════════════════════════
//  AUDIT LOG SECTION
// ════════════════════════════════════════════════════════════════

async function loadAuditSection() {
  try {
    const stats = await DB.getAuditStats();
    if (auditTotalMetric) auditTotalMetric.textContent = stats.total.toLocaleString();
    if (auditCriticalMetric) auditCriticalMetric.textContent = stats.critical24h;
  } catch (_) { }
  await loadAuditLogs();
}

async function loadAuditLogs(search = '') {
  if (!auditLogBody) return;
  auditLogBody.innerHTML = skeletonRows(5);
  try {
    const { data } = await DB.getAuditLogs({ search });
    renderAuditLogs(data || []);
  } catch (err) {
    auditLogBody.innerHTML = '<tr><td colspan="5" class="muted" style="text-align:center">Failed to load audit logs.</td></tr>';
  }
}

function renderAuditLogs(logs) {
  if (!auditLogBody) return;
  if (!logs.length) {
    auditLogBody.innerHTML = '<tr><td colspan="5" class="muted" style="text-align:center;padding:2rem">No audit entries.</td></tr>';
    return;
  }
  auditLogBody.innerHTML = logs.map(l => `
    <tr>
      <td>${formatDate(l.created_at)}</td>
      <td>${escapeHtml(l.users?.username || '—')}</td>
      <td>${escapeHtml(l.module)}</td>
      <td>${escapeHtml(l.action)}</td>
      <td>${statusBadge(l.result)}</td>
    </tr>`).join('');
}

if (auditSearchInput) {
  auditSearchInput.addEventListener('input', debounce((e) => {
    loadAuditLogs(e.target.value.trim());
  }, SEARCH_DEBOUNCE_MS));
}

// ════════════════════════════════════════════════════════════════
//  REPORTS SECTION
// ════════════════════════════════════════════════════════════════

async function loadReportsSection() {
  await loadDocuments();
}

async function loadDocuments() {
  if (!documentTableBody) return;
  try {
    const docs = await DB.getDocuments();
    documentTableBody.innerHTML = docs.map(d => `
      <tr>
        <td>${escapeHtml(d.title)}</td>
        <td>${escapeHtml(d.doc_type)}</td>
        <td>${toInputDate(d.uploaded_at)}</td>
        <td><button type="button" class="action-btn" data-url="${escapeHtml(d.file_url || '')}">Download</button></td>
      </tr>`).join('');
  } catch (_) { }
}

// Report generation
if (generatePrivacyBtn) {
  generatePrivacyBtn.addEventListener('click', () => {
    if (reportStatus) reportStatus.textContent = `RA 10173 compliance report generated on ${formatDate(new Date())}.`;
    showToast('RA 10173 report generated.', 'success');
  });
}

if (generateCyberBtn) {
  generateCyberBtn.addEventListener('click', () => {
    if (reportStatus) reportStatus.textContent = `RA 10175 cybersecurity report generated on ${formatDate(new Date())}.`;
    showToast('RA 10175 report generated.', 'success');
  });
}

// PDF/Excel export stubs
if (exportPdfBtn) {
  exportPdfBtn.addEventListener('click', async () => {
    showToast('PDF export — install jsPDF to enable.', 'info');
    if (reportStatus) reportStatus.textContent = `PDF export triggered on ${formatDate(new Date())}.`;
  });
}

if (exportExcelBtn) {
  exportExcelBtn.addEventListener('click', async () => {
    showToast('Excel export — install SheetJS to enable.', 'info');
    if (reportStatus) reportStatus.textContent = `Excel export triggered on ${formatDate(new Date())}.`;
  });
}

// ════════════════════════════════════════════════════════════════
//  REALTIME SUBSCRIPTIONS
// ════════════════════════════════════════════════════════════════

function setupRealtime() {
  teardownRealtime();

  // Reports changes → refresh dashboard
  _realtimeChannels.push(DB.subscribeToTable('reports', () => {
    const activePanel = document.querySelector('.panel.active');
    if (activePanel?.id === 'dashboard') loadDashboard();
  }));

  // Controls changes → refresh compliance
  _realtimeChannels.push(DB.subscribeToTable('compliance_controls', () => {
    const activePanel = document.querySelector('.panel.active');
    if (activePanel?.id === 'compliance-checker') loadComplianceControls();
  }));

  // Notifications → update badge
  _realtimeChannels.push(DB.subscribeToTable('notifications', async () => {
    const user = Auth.getCurrentUser();
    const count = await DB.getUnreadCount(user?.id);
    updateAlertBadge(count);
  }));

  // Audit logs → refresh if viewing
  _realtimeChannels.push(DB.subscribeToTable('audit_logs', () => {
    const activePanel = document.querySelector('.panel.active');
    if (activePanel?.id === 'audit-log') loadAuditSection();
  }));
}

function teardownRealtime() {
  _realtimeChannels.forEach(ch => { try { supabase.removeChannel(ch); } catch (_) { } });
  _realtimeChannels = [];
}

// ════════════════════════════════════════════════════════════════
//  GLOBAL SEARCH (top bar)
// ════════════════════════════════════════════════════════════════

if (dashSearchInput) {
  dashSearchInput.addEventListener('input', debounce(async (e) => {
    const q = e.target.value.trim();
    if (!q) return;
    // Navigate to reports and search
    setActiveSection('reports');
    // could expand to multi-table search in future
  }, SEARCH_DEBOUNCE_MS));
}
