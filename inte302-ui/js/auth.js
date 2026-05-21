/**
 * @fileoverview CompliTrack — Authentication & session management via Supabase Auth.
 * Handles sign-in, sign-out, MFA, session refresh, and audit logging.
 */

import { supabase, AUDIT_MODULES, ROLE_LEVELS } from './config.js';
import { showToast } from './utils.js';

/** @type {object|null} Current authenticated user profile. */
let _currentUser = null;

/**
 * Get the currently cached user profile.
 * @returns {object|null}
 */
export function getCurrentUser() {
  return _currentUser;
}

/**
 * Check whether the current user has at least the given role level.
 * @param {string} requiredRole - Minimum role key.
 * @returns {boolean}
 */
export function hasRole(requiredRole) {
  if (!_currentUser) return false;
  return (ROLE_LEVELS[_currentUser.role] || 0) >= (ROLE_LEVELS[requiredRole] || 99);
}

/**
 * Sign in with email/password using Supabase Auth.
 * @param {string} email
 * @param {string} password
 * @returns {Promise<{user: object|null, error: string|null}>}
 */
export async function signIn(email, password) {
  try {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) {
      await logAuditEvent(AUDIT_MODULES.AUTH, `Login failed: ${email}`, 'Failed');
      return { user: null, error: error.message };
    }
    // Fetch the app-level user profile
    const profile = await fetchUserProfile(data.user.id);
    _currentUser = profile;
    // Update last_login
    await supabase.from('users').update({ last_login: new Date().toISOString() }).eq('id', data.user.id);
    await logAuditEvent(AUDIT_MODULES.AUTH, `User signed in: ${email}`, 'Success');
    return { user: profile, error: null };
  } catch (err) {
    return { user: null, error: err.message || 'Network error' };
  }
}

/**
 * Sign out the current user.
 * @returns {Promise<void>}
 */
export async function signOut() {
  try {
    if (_currentUser) {
      await logAuditEvent(AUDIT_MODULES.AUTH, `User signed out: ${_currentUser.email}`, 'Success');
    }
    await supabase.auth.signOut();
  } catch (_) {
    /* best-effort */
  } finally {
    _currentUser = null;
  }
}

/**
 * Sign up a new user via Supabase Auth and insert an app-level profile.
 * @param {object} opts
 * @param {string} opts.email
 * @param {string} opts.password
 * @param {string} opts.username
 * @param {string} [opts.role='viewer']
 * @returns {Promise<{user: object|null, error: string|null}>}
 */
export async function signUp({ email, password, username, role = 'viewer' }) {
  try {
    const { data, error } = await supabase.auth.signUp({ email, password });
    if (error) return { user: null, error: error.message };

    // Insert app-level user profile
    const { error: insertErr } = await supabase.from('users').insert({
      id: data.user.id,
      email,
      username,
      password_hash: '(managed by Supabase Auth)',
      role,
    });
    if (insertErr) return { user: null, error: insertErr.message };

    await logAuditEvent(AUDIT_MODULES.AUTH, `New user registered: ${email}`, 'Success');
    return { user: data.user, error: null };
  } catch (err) {
    return { user: null, error: err.message };
  }
}

/**
 * Send a password reset email.
 * @param {string} email
 * @returns {Promise<{error: string|null}>}
 */
export async function resetPassword(email) {
  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: window.location.origin,
  });
  return { error: error ? error.message : null };
}

/**
 * Enrol the current user in TOTP MFA.
 * @returns {Promise<{qr: string|null, error: string|null}>}
 */
export async function enrollMfa() {
  try {
    const { data, error } = await supabase.auth.mfa.enroll({ factorType: 'totp' });
    if (error) return { qr: null, error: error.message };
    // Update profile flag
    if (_currentUser) {
      await supabase.from('users').update({ mfa_enabled: true }).eq('id', _currentUser.id);
      _currentUser.mfa_enabled = true;
    }
    return { qr: data.totp.qr_code, error: null };
  } catch (err) {
    return { qr: null, error: err.message };
  }
}

/**
 * Verify MFA TOTP code.
 * @param {string} factorId
 * @param {string} code
 * @returns {Promise<{verified: boolean, error: string|null}>}
 */
export async function verifyMfa(factorId, code) {
  try {
    const { data: challenge } = await supabase.auth.mfa.challenge({ factorId });
    const { data, error } = await supabase.auth.mfa.verify({
      factorId,
      challengeId: challenge.id,
      code,
    });
    if (error) {
      await logAuditEvent(AUDIT_MODULES.AUTH, 'MFA verification failed', 'Alert');
      return { verified: false, error: error.message };
    }
    await logAuditEvent(AUDIT_MODULES.AUTH, 'MFA verification succeeded', 'Success');
    return { verified: true, error: null };
  } catch (err) {
    return { verified: false, error: err.message };
  }
}

/**
 * Restore session on page load.
 * @returns {Promise<object|null>} User profile or null.
 */
export async function restoreSession() {
  try {
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return null;
    _currentUser = await fetchUserProfile(session.user.id);
    return _currentUser;
  } catch (_) {
    return null;
  }
}

/**
 * Listen for auth state changes.
 * @param {Function} callback - Receives (event, session).
 * @returns {object} Subscription handle with `unsubscribe()`.
 */
export function onAuthStateChange(callback) {
  const { data } = supabase.auth.onAuthStateChange(callback);
  return data.subscription;
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Fetch the app-level user profile from the users table.
 * @param {string} userId
 * @returns {Promise<object|null>}
 */
async function fetchUserProfile(userId) {
  const { data, error } = await supabase
    .from('users')
    .select('id, username, email, role, mfa_enabled, created_at, last_login')
    .eq('id', userId)
    .single();
  if (error) return null;
  return data;
}

/**
 * Insert an audit log entry.
 * @param {string} module
 * @param {string} action
 * @param {string} result
 */
async function logAuditEvent(module, action, result) {
  try {
    await supabase.from('audit_logs').insert({
      user_id: _currentUser?.id || null,
      module,
      action,
      result,
      ip_address: 'local',
      user_agent: navigator.userAgent,
    });
  } catch (_) {
    /* best-effort — never block auth flow */
  }
}
