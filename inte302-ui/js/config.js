/**
 * @fileoverview CompliTrack — Supabase configuration.
 * Replace placeholders with your Supabase project URL and anon key.
 */

const SUPABASE_URL = 'https://ywuipsaspjeljbkdsnwd.supabase.co';
const SUPABASE_ANON = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inl3dWlwc2FzcGplbGpia2RzbndkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzkxODI5NzYsImV4cCI6MjA5NDc1ODk3Nn0.CxWH5eU-u2rnzD8QfiWIwQJb4pQ7fVhWxIoSmvpev88';

const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON, {
  auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true },
  realtime: { params: { eventsPerSecond: 10 } },
});

const PAGE_SIZE = 20;
const SEARCH_DEBOUNCE_MS = 350;
const MAX_RETRIES = 3;

const AUDIT_MODULES = Object.freeze({
  AUTH: 'Authentication',
  COMPLIANCE: 'Compliance',
  ACCESS: 'Access control',
  REPORTS: 'Reports',
  DOCUMENTS: 'Documents',
});

const ROLE_LEVELS = Object.freeze({
  viewer: 1, auditor: 2, compliance_officer: 3, admin: 4,
});

export { supabase, SUPABASE_URL, PAGE_SIZE, SEARCH_DEBOUNCE_MS, MAX_RETRIES, AUDIT_MODULES, ROLE_LEVELS };
