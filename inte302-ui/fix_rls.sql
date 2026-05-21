-- ============================================================
-- CompliTrack — RLS Fix for Presentation / Testing
-- ============================================================
-- Run this in Supabase SQL Editor AFTER the main schema.sql
-- This fixes 500 errors caused by recursive RLS policies
-- ============================================================

-- Drop the problematic recursive policies
DROP POLICY IF EXISTS "Users: self-read" ON public.users;
DROP POLICY IF EXISTS "Users: admin-manage" ON public.users;
DROP POLICY IF EXISTS "Reports: own-read" ON public.reports;
DROP POLICY IF EXISTS "Audit: admin-auditor-read" ON public.audit_logs;

-- Replace with simple, non-recursive policies for presentation
-- Users: can read own profile
CREATE POLICY "Users: read-own" ON public.users
  FOR SELECT USING (auth.uid()::text = id::text);

-- Users: can update own profile
CREATE POLICY "Users: update-own" ON public.users
  FOR UPDATE USING (auth.uid()::text = id::text);

-- Reports: all authenticated users can read all reports
CREATE POLICY "Reports: authenticated-read" ON public.reports
  FOR SELECT USING (auth.role() = 'authenticated');

-- Audit logs: all authenticated users can read
CREATE POLICY "Audit: authenticated-read" ON public.audit_logs
  FOR SELECT USING (auth.role() = 'authenticated');
