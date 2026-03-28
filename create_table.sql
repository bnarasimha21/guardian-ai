-- Run this in Supabase SQL Editor (Dashboard > SQL Editor > New Query)

CREATE TABLE IF NOT EXISTS guardian_ai_usage (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT now(),
    session_id TEXT,
    event_type TEXT NOT NULL,              -- 'app_connected', 'app_disconnected', 'threat_blocked', 'session_started'
    app_name TEXT,                          -- target app name (e.g., 'ArchitectAI')
    app_url TEXT,                           -- target app URL
    rule_name TEXT,                         -- guardian rule that triggered (for blocked events)
    owasp_id TEXT,                          -- OWASP LLM category (e.g., 'LLM01')
    threat_level TEXT,                      -- none, low, medium, high, critical
    reason TEXT,                            -- human-readable reason for the decision
    total_events_checked INTEGER DEFAULT 0, -- running total at time of log
    total_blocked INTEGER DEFAULT 0,        -- running total at time of log
    user_agent TEXT,
    ip_address TEXT
);

-- Enable Row Level Security but allow inserts from anon
ALTER TABLE guardian_ai_usage ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow anonymous inserts" ON guardian_ai_usage
    FOR INSERT TO anon WITH CHECK (true);

CREATE POLICY "Allow anonymous reads" ON guardian_ai_usage
    FOR SELECT TO anon USING (true);

-- Indexes
CREATE INDEX idx_guardian_usage_created_at ON guardian_ai_usage(created_at DESC);
CREATE INDEX idx_guardian_usage_session ON guardian_ai_usage(session_id);
CREATE INDEX idx_guardian_usage_event_type ON guardian_ai_usage(event_type);
