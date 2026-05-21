/**
 * @fileoverview CompliTrack — Database service layer.
 * All Supabase CRUD operations, realtime subscriptions, and data queries.
 */

import { supabase, PAGE_SIZE, AUDIT_MODULES } from './config.js';
import { withRetry, SimpleCache } from './utils.js';

const _cache = new SimpleCache(5 * 60 * 1000);

// ════════════════════════════════════════════════════════════════
//  FRAMEWORKS
// ════════════════════════════════════════════════════════════════

/** Fetch all compliance frameworks (cached). */
export async function getFrameworks() {
  const cached = _cache.get('frameworks');
  if (cached) return cached;
  const { data, error } = await withRetry(() =>
    supabase.from('compliance_frameworks').select('id, code, title, description').order('code')
  );
  if (error) throw new Error(error.message);
  _cache.set('frameworks', data);
  return data;
}

// ════════════════════════════════════════════════════════════════
//  COMPLIANCE CONTROLS
// ════════════════════════════════════════════════════════════════

/**
 * Fetch controls with optional framework filter.
 * @param {object} opts
 * @param {string} [opts.frameworkCode] - 'RA 10173', 'RA 10175', or 'ALL'.
 * @param {number} [opts.page=0]
 */
export async function getControls({ frameworkCode = 'ALL', page = 0 } = {}) {
  let query = supabase
    .from('compliance_controls')
    .select('*, compliance_frameworks!inner(code, title)', { count: 'exact' })
    .order('control_id')
    .range(page * PAGE_SIZE, (page + 1) * PAGE_SIZE - 1);

  if (frameworkCode && frameworkCode !== 'ALL') {
    query = query.eq('compliance_frameworks.code', frameworkCode);
  }
  const { data, error, count } = await withRetry(() => query);
  if (error) throw new Error(error.message);
  return { data, count };
}

/** Update a single control's status. */
export async function updateControlStatus(controlId, newStatus) {
  const { data, error } = await supabase
    .from('compliance_controls')
    .update({ status: newStatus })
    .eq('id', controlId)
    .select()
    .single();
  if (error) throw new Error(error.message);
  await insertAuditLog(AUDIT_MODULES.COMPLIANCE, `Control status → ${newStatus}`, data.control_id);
  return data;
}

// ════════════════════════════════════════════════════════════════
//  VIOLATIONS
// ════════════════════════════════════════════════════════════════

export async function getViolations({ page = 0 } = {}) {
  const { data, error, count } = await withRetry(() =>
    supabase
      .from('violations')
      .select('*, compliance_controls(control_id)', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range(page * PAGE_SIZE, (page + 1) * PAGE_SIZE - 1)
  );
  if (error) throw new Error(error.message);
  return { data, count };
}

export async function updateViolationStatus(id, newStatus) {
  const { data, error } = await supabase
    .from('violations')
    .update({ status: newStatus })
    .eq('id', id)
    .select()
    .single();
  if (error) throw new Error(error.message);
  await insertAuditLog(AUDIT_MODULES.COMPLIANCE, `Violation status → ${newStatus}`, data.violation_id);
  return data;
}

// ════════════════════════════════════════════════════════════════
//  REPORTS
// ════════════════════════════════════════════════════════════════

/**
 * Fetch reports with pagination, search, and status filter.
 * @param {object} opts
 * @param {number} [opts.page=0]
 * @param {string} [opts.search]
 * @param {string} [opts.status]
 */
export async function getReports({ page = 0, search = '', status = '' } = {}) {
  let query = supabase
    .from('reports')
    .select('*', { count: 'exact' })
    .order('date_submitted', { ascending: false })
    .range(page * PAGE_SIZE, (page + 1) * PAGE_SIZE - 1);

  if (status) query = query.eq('status', status);
  if (search) query = query.or(`title.ilike.%${search}%,department.ilike.%${search}%,report_id.ilike.%${search}%`);

  const { data, error, count } = await withRetry(() => query);
  if (error) throw new Error(error.message);
  return { data, count };
}

/** Submit a new compliance report. */
export async function createReport({ title, department, summary, fileUrl, submittedBy, frameworkId }) {
  const { data, error } = await supabase
    .from('reports')
    .insert({
      title,
      department,
      summary,
      file_url: fileUrl || null,
      submitted_by: submittedBy || null,
      framework_id: frameworkId || null,
      status: 'Pending',
    })
    .select()
    .single();
  if (error) throw new Error(error.message);
  await insertAuditLog(AUDIT_MODULES.REPORTS, `Report submitted: ${data.report_id}`, data.report_id);
  return data;
}

/** Update report status (approve/reject). */
export async function updateReportStatus(id, newStatus, reviewerId) {
  const updates = { status: newStatus };
  if (reviewerId) {
    updates.reviewed_by = reviewerId;
    updates.reviewed_date = new Date().toISOString();
  }
  const { data, error } = await supabase.from('reports').update(updates).eq('id', id).select().single();
  if (error) throw new Error(error.message);
  await insertAuditLog(AUDIT_MODULES.REPORTS, `Report ${data.report_id} → ${newStatus}`, data.report_id);
  return data;
}

/** Get dashboard report statistics. */
export async function getReportStats() {
  const { data, error } = await supabase.from('reports').select('status');
  if (error) throw new Error(error.message);
  const stats = { total: data.length, pending: 0, approved: 0, rejected: 0, underReview: 0 };
  data.forEach(r => {
    if (r.status === 'Pending') stats.pending++;
    else if (r.status === 'Approved') stats.approved++;
    else if (r.status === 'Rejected') stats.rejected++;
    else if (r.status === 'Under Review') stats.underReview++;
  });
  return stats;
}

// ════════════════════════════════════════════════════════════════
//  AUDIT LOGS
// ════════════════════════════════════════════════════════════════

export async function getAuditLogs({ page = 0, search = '' } = {}) {
  let query = supabase
    .from('audit_logs')
    .select('*, users(username)', { count: 'exact' })
    .order('created_at', { ascending: false })
    .range(page * PAGE_SIZE, (page + 1) * PAGE_SIZE - 1);

  if (search) query = query.or(`action.ilike.%${search}%,module.ilike.%${search}%`);

  const { data, error, count } = await withRetry(() => query);
  if (error) throw new Error(error.message);
  return { data, count };
}

export async function getAuditStats() {
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const [totalRes, criticalRes] = await Promise.all([
    supabase.from('audit_logs').select('id', { count: 'exact', head: true }),
    supabase.from('audit_logs').select('id', { count: 'exact', head: true }).eq('result', 'Alert').gte('created_at', since),
  ]);
  return {
    total: totalRes.count || 0,
    critical24h: criticalRes.count || 0,
  };
}

/** Insert an audit log entry (internal helper). */
export async function insertAuditLog(module, action, resource = null, result = 'Success') {
  try {
    const { data: { session } } = await supabase.auth.getSession();
    await supabase.from('audit_logs').insert({
      user_id: session?.user?.id || null,
      module,
      action,
      affected_resource: resource,
      result,
      ip_address: 'local',
      user_agent: navigator.userAgent,
    });
  } catch (_) { /* best-effort */ }
}

// ════════════════════════════════════════════════════════════════
//  DOCUMENTS
// ════════════════════════════════════════════════════════════════

export async function getDocuments() {
  const { data, error } = await withRetry(() =>
    supabase.from('documents').select('*').order('uploaded_at', { ascending: false })
  );
  if (error) throw new Error(error.message);
  return data;
}

export async function uploadDocument({ title, docType, fileUrl, frameworkId, uploadedBy }) {
  const { data, error } = await supabase.from('documents').insert({
    title, doc_type: docType, file_url: fileUrl,
    framework_id: frameworkId || null, uploaded_by: uploadedBy || null,
  }).select().single();
  if (error) throw new Error(error.message);
  await insertAuditLog(AUDIT_MODULES.DOCUMENTS, `Document uploaded: ${title}`, data.id);
  return data;
}

// ════════════════════════════════════════════════════════════════
//  NOTIFICATIONS
// ════════════════════════════════════════════════════════════════

export async function getNotifications(userId) {
  let query = supabase
    .from('notifications')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(20);

  if (userId) {
    query = query.or(`user_id.eq.${userId},user_id.is.null`);
  } else {
    query = query.is('user_id', null);
  }

  const { data, error } = await withRetry(() => query);
  if (error) throw new Error(error.message);
  return data;
}

export async function markNotificationRead(id) {
  const { error } = await supabase.from('notifications').update({ read: true }).eq('id', id);
  if (error) throw new Error(error.message);
}

export async function getUnreadCount(userId) {
  let query = supabase
    .from('notifications')
    .select('id', { count: 'exact', head: true })
    .eq('read', false);
  if (userId) {
    query = query.or(`user_id.eq.${userId},user_id.is.null`);
  } else {
    query = query.is('user_id', null);
  }
  const { count, error } = await query;
  if (error) return 0;
  return count || 0;
}

// ════════════════════════════════════════════════════════════════
//  REALTIME SUBSCRIPTIONS
// ════════════════════════════════════════════════════════════════

/**
 * Subscribe to realtime changes on a table.
 * @param {string} table - Table name.
 * @param {Function} callback - Receives the payload.
 * @returns {object} Subscription channel (call .unsubscribe() to stop).
 */
export function subscribeToTable(table, callback) {
  const channel = supabase
    .channel(`realtime-${table}`)
    .on('postgres_changes', { event: '*', schema: 'public', table }, callback)
    .subscribe();
  return channel;
}

/** Clear all cached data. */
export function clearCache() {
  _cache.clear();
}
