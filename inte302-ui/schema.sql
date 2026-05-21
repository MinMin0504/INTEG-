-- ============================================================
-- CompliTrack — Supabase PostgreSQL Schema Migration
-- Compliance Tracking and Reporting System
-- ============================================================
-- Run this in the Supabase SQL Editor (Dashboard → SQL Editor)
-- ============================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================
-- 1. USERS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS public.users (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username      TEXT NOT NULL UNIQUE,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'viewer'
                CHECK (role IN ('admin','compliance_officer','auditor','viewer')),
  mfa_enabled   BOOLEAN NOT NULL DEFAULT FALSE,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login    TIMESTAMPTZ
);

CREATE INDEX idx_users_role       ON public.users (role);
CREATE INDEX idx_users_username   ON public.users (username);

-- ============================================================
-- 2. COMPLIANCE FRAMEWORKS
-- ============================================================
CREATE TABLE IF NOT EXISTS public.compliance_frameworks (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  code        TEXT NOT NULL UNIQUE,
  title       TEXT NOT NULL,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================
-- 3. COMPLIANCE CONTROLS
-- ============================================================
CREATE TABLE IF NOT EXISTS public.compliance_controls (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  control_id    TEXT NOT NULL UNIQUE,
  framework_id  UUID NOT NULL REFERENCES public.compliance_frameworks(id) ON DELETE CASCADE,
  requirement   TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'Needs Review'
                CHECK (status IN ('Compliant','Needs Review','Non-Compliant')),
  owner         TEXT,
  due_date      DATE,
  evidence_url  TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_controls_framework ON public.compliance_controls (framework_id);
CREATE INDEX idx_controls_status    ON public.compliance_controls (status);

-- ============================================================
-- 4. VIOLATIONS
-- ============================================================
CREATE TABLE IF NOT EXISTS public.violations (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  violation_id      TEXT NOT NULL UNIQUE,
  control_id        UUID REFERENCES public.compliance_controls(id) ON DELETE SET NULL,
  issue             TEXT NOT NULL,
  severity          TEXT NOT NULL CHECK (severity IN ('High','Medium','Low')),
  corrective_action TEXT,
  status            TEXT NOT NULL DEFAULT 'Open'
                    CHECK (status IN ('Open','In progress','Pending','Resolved')),
  assigned_to       UUID REFERENCES public.users(id) ON DELETE SET NULL,
  due_date          DATE,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_violations_status   ON public.violations (status);
CREATE INDEX idx_violations_severity ON public.violations (severity);

-- ============================================================
-- 5. REPORTS
-- ============================================================
CREATE TABLE IF NOT EXISTS public.reports (
  id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  report_id      TEXT NOT NULL UNIQUE,
  title          TEXT NOT NULL,
  department     TEXT NOT NULL,
  submitted_by   UUID REFERENCES public.users(id) ON DELETE SET NULL,
  status         TEXT NOT NULL DEFAULT 'Pending'
                 CHECK (status IN ('Pending','Under Review','Approved','Rejected')),
  framework_id   UUID REFERENCES public.compliance_frameworks(id) ON DELETE SET NULL,
  file_url       TEXT,
  summary        TEXT,
  date_submitted TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reviewed_by    UUID REFERENCES public.users(id) ON DELETE SET NULL,
  reviewed_date  TIMESTAMPTZ
);

CREATE INDEX idx_reports_status      ON public.reports (status);
CREATE INDEX idx_reports_submitted   ON public.reports (date_submitted DESC);
CREATE INDEX idx_reports_submitted_by ON public.reports (submitted_by);

-- ============================================================
-- 6. AUDIT LOGS  (immutable — no UPDATE/DELETE allowed via RLS)
-- ============================================================
CREATE TABLE IF NOT EXISTS public.audit_logs (
  id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id           UUID REFERENCES public.users(id) ON DELETE SET NULL,
  module            TEXT NOT NULL,
  action            TEXT NOT NULL,
  affected_resource TEXT,
  result            TEXT NOT NULL DEFAULT 'Success'
                    CHECK (result IN ('Success','Alert','Failed')),
  ip_address        TEXT,
  user_agent        TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_user      ON public.audit_logs (user_id);
CREATE INDEX idx_audit_module    ON public.audit_logs (module);
CREATE INDEX idx_audit_created   ON public.audit_logs (created_at DESC);

-- ============================================================
-- 7. DOCUMENTS
-- ============================================================
CREATE TABLE IF NOT EXISTS public.documents (
  id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  title         TEXT NOT NULL,
  doc_type      TEXT NOT NULL CHECK (doc_type IN ('Permit','Certificate','Evidence','Report')),
  uploaded_by   UUID REFERENCES public.users(id) ON DELETE SET NULL,
  file_url      TEXT NOT NULL,
  framework_id  UUID REFERENCES public.compliance_frameworks(id) ON DELETE SET NULL,
  uploaded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_documents_type ON public.documents (doc_type);

-- ============================================================
-- 8. NOTIFICATIONS
-- ============================================================
CREATE TABLE IF NOT EXISTS public.notifications (
  id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id     UUID REFERENCES public.users(id) ON DELETE CASCADE,
  title       TEXT NOT NULL,
  message     TEXT NOT NULL,
  type        TEXT NOT NULL DEFAULT 'info'
              CHECK (type IN ('info','warning','critical')),
  read        BOOLEAN NOT NULL DEFAULT FALSE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notifications_user    ON public.notifications (user_id);
CREATE INDEX idx_notifications_read    ON public.notifications (read);
CREATE INDEX idx_notifications_created ON public.notifications (created_at DESC);

-- ============================================================
-- AUTO-UPDATE updated_at TRIGGER
-- ============================================================
CREATE OR REPLACE FUNCTION public.update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_controls_updated
  BEFORE UPDATE ON public.compliance_controls
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

CREATE TRIGGER trg_violations_updated
  BEFORE UPDATE ON public.violations
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- ============================================================
-- AUTO-INCREMENT REPORT ID SEQUENCE
-- ============================================================
CREATE SEQUENCE IF NOT EXISTS public.report_id_seq START WITH 505;

CREATE OR REPLACE FUNCTION public.set_report_id()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.report_id IS NULL OR NEW.report_id = '' THEN
    NEW.report_id = 'REP-' || nextval('public.report_id_seq');
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_report_id
  BEFORE INSERT ON public.reports
  FOR EACH ROW EXECUTE FUNCTION public.set_report_id();

-- ============================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================

-- Enable RLS on all tables
ALTER TABLE public.users              ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.compliance_frameworks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.compliance_controls ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.violations         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reports            ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.documents          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications      ENABLE ROW LEVEL SECURITY;

-- ---------- USERS ----------
-- Users can read their own profile; admins can read all
CREATE POLICY "Users: self-read" ON public.users
  FOR SELECT USING (
    auth.uid()::text = id::text
    OR EXISTS (SELECT 1 FROM public.users u WHERE u.id::text = auth.uid()::text AND u.role = 'admin')
  );

CREATE POLICY "Users: admin-manage" ON public.users
  FOR ALL USING (
    EXISTS (SELECT 1 FROM public.users u WHERE u.id::text = auth.uid()::text AND u.role = 'admin')
  );

-- ---------- FRAMEWORKS ----------
-- Everyone can read frameworks
CREATE POLICY "Frameworks: public-read" ON public.compliance_frameworks
  FOR SELECT USING (true);

CREATE POLICY "Frameworks: admin-manage" ON public.compliance_frameworks
  FOR ALL USING (
    EXISTS (SELECT 1 FROM public.users u WHERE u.id::text = auth.uid()::text AND u.role = 'admin')
  );

-- ---------- CONTROLS ----------
CREATE POLICY "Controls: authenticated-read" ON public.compliance_controls
  FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "Controls: officer-manage" ON public.compliance_controls
  FOR ALL USING (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id::text = auth.uid()::text
      AND u.role IN ('admin','compliance_officer')
    )
  );

-- ---------- VIOLATIONS ----------
CREATE POLICY "Violations: authenticated-read" ON public.violations
  FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "Violations: officer-manage" ON public.violations
  FOR ALL USING (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id::text = auth.uid()::text
      AND u.role IN ('admin','compliance_officer','auditor')
    )
  );

-- ---------- REPORTS ----------
CREATE POLICY "Reports: own-read" ON public.reports
  FOR SELECT USING (
    submitted_by::text = auth.uid()::text
    OR EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id::text = auth.uid()::text
      AND u.role IN ('admin','compliance_officer','auditor')
    )
  );

CREATE POLICY "Reports: authenticated-insert" ON public.reports
  FOR INSERT WITH CHECK (auth.role() = 'authenticated');

CREATE POLICY "Reports: reviewer-update" ON public.reports
  FOR UPDATE USING (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id::text = auth.uid()::text
      AND u.role IN ('admin','compliance_officer')
    )
  );

-- ---------- AUDIT LOGS (immutable — insert-only) ----------
CREATE POLICY "Audit: insert-only" ON public.audit_logs
  FOR INSERT WITH CHECK (auth.role() = 'authenticated');

CREATE POLICY "Audit: admin-auditor-read" ON public.audit_logs
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id::text = auth.uid()::text
      AND u.role IN ('admin','auditor')
    )
  );

-- ---------- DOCUMENTS ----------
CREATE POLICY "Docs: authenticated-read" ON public.documents
  FOR SELECT USING (auth.role() = 'authenticated');

CREATE POLICY "Docs: authenticated-insert" ON public.documents
  FOR INSERT WITH CHECK (auth.role() = 'authenticated');

-- ---------- NOTIFICATIONS ----------
CREATE POLICY "Notifs: own-or-broadcast" ON public.notifications
  FOR SELECT USING (
    user_id IS NULL
    OR user_id::text = auth.uid()::text
  );

CREATE POLICY "Notifs: update-own" ON public.notifications
  FOR UPDATE USING (
    user_id::text = auth.uid()::text
  );

CREATE POLICY "Notifs: admin-insert" ON public.notifications
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.users u
      WHERE u.id::text = auth.uid()::text
      AND u.role IN ('admin','compliance_officer')
    )
  );

-- ============================================================
-- SEED DATA — Philippine Compliance Frameworks
-- ============================================================
INSERT INTO public.compliance_frameworks (code, title, description) VALUES
  ('RA 10173', 'Data Privacy Act of 2012',
   'An Act Protecting Individual Personal Information in Information and Communications Systems in the Government and the Private Sector.'),
  ('RA 10175', 'Cybercrime Prevention Act of 2012',
   'An Act Defining Cybercrime, Providing for the Prevention, Investigation, Suppression and the Imposition of Penalties.')
ON CONFLICT (code) DO NOTHING;

-- Seed compliance controls
INSERT INTO public.compliance_controls (control_id, framework_id, requirement, status, owner, due_date) VALUES
  ('CTRL-101',
   (SELECT id FROM public.compliance_frameworks WHERE code = 'RA 10173'),
   'Consent and lawful processing', 'Compliant', 'DPO Office', '2026-05-20'),
  ('CTRL-102',
   (SELECT id FROM public.compliance_frameworks WHERE code = 'RA 10173'),
   'Data retention and disposal', 'Needs Review', 'Compliance Team', '2026-05-18'),
  ('CTRL-103',
   (SELECT id FROM public.compliance_frameworks WHERE code = 'RA 10173'),
   'Breach notification procedures', 'Compliant', 'DPO Office', '2026-06-01'),
  ('CTRL-201',
   (SELECT id FROM public.compliance_frameworks WHERE code = 'RA 10175'),
   'Incident reporting response time', 'Compliant', 'SOC Team', '2026-05-16'),
  ('CTRL-202',
   (SELECT id FROM public.compliance_frameworks WHERE code = 'RA 10175'),
   'Access abuse monitoring', 'Non-Compliant', 'IT Security', '2026-05-14')
ON CONFLICT (control_id) DO NOTHING;

-- Seed violations
INSERT INTO public.violations (violation_id, control_id, issue, severity, corrective_action, status, due_date) VALUES
  ('V-301',
   (SELECT id FROM public.compliance_controls WHERE control_id = 'CTRL-101'),
   'Missing consent evidence', 'High', 'Collect updated consent forms', 'Open', '2026-05-25'),
  ('V-302',
   (SELECT id FROM public.compliance_controls WHERE control_id = 'CTRL-201'),
   'Delayed cyber incident reporting', 'Medium', 'Enforce 24h escalation workflow', 'In progress', '2026-05-30'),
  ('V-303',
   (SELECT id FROM public.compliance_controls WHERE control_id = 'CTRL-103'),
   'Expired compliance certificate', 'Low', 'Renew and re-upload certificate', 'Pending', '2026-06-10')
ON CONFLICT (violation_id) DO NOTHING;

-- Seed documents
INSERT INTO public.documents (title, doc_type, file_url) VALUES
  ('Business Permit 2026', 'Permit', '/documents/business-permit-2026.pdf'),
  ('Data Privacy Certification', 'Certificate', '/documents/dpa-cert-2026.pdf'),
  ('Q1 Compliance Evidence Pack', 'Evidence', '/documents/q1-evidence-2026.zip')
ON CONFLICT DO NOTHING;

-- Seed broadcast notifications
INSERT INTO public.notifications (user_id, title, message, type) VALUES
  (NULL, 'Missing Report', 'Missing compliance report from Procurement team.', 'warning'),
  (NULL, 'Deadline Reminder', 'RA 10175 monthly report due in 2 days.', 'critical'),
  (NULL, 'Status Update', 'REP-502 moved to Under Review.', 'info')
ON CONFLICT DO NOTHING;

-- Seed sample reports
INSERT INTO public.reports (report_id, title, department, status, summary, date_submitted) VALUES
  ('REP-501', 'Q2 HR Compliance Summary', 'HR', 'Approved',
   'All HR data handling processes reviewed and compliant with RA 10173.', '2026-05-12 10:20:00+08'),
  ('REP-502', 'Finance Data Audit', 'Finance', 'Under Review',
   'Financial records access controls under review for RA 10175 compliance.', '2026-05-12 09:03:00+08'),
  ('REP-503', 'IT Infrastructure Assessment', 'IT', 'Pending',
   'Cybersecurity posture assessment pending SOC team review.', '2026-05-11 16:42:00+08'),
  ('REP-504', 'Operations Risk Report', 'Operations', 'Rejected',
   'Incomplete evidence for data processing consent requirements.', '2026-05-11 14:25:00+08')
ON CONFLICT (report_id) DO NOTHING;

-- ============================================================
-- REALTIME — Enable for critical tables
-- ============================================================
-- Run these via Supabase Dashboard → Database → Replication
-- or use:
-- ALTER PUBLICATION supabase_realtime ADD TABLE public.compliance_controls;
-- ALTER PUBLICATION supabase_realtime ADD TABLE public.violations;
-- ALTER PUBLICATION supabase_realtime ADD TABLE public.reports;
-- ALTER PUBLICATION supabase_realtime ADD TABLE public.notifications;
-- ALTER PUBLICATION supabase_realtime ADD TABLE public.audit_logs;

-- ============================================================
-- DONE — Schema ready for CompliTrack
-- ============================================================
