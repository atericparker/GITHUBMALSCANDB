
-- optional: enum for high-level scan outcome
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'scan_outcome') THEN
    CREATE TYPE scan_outcome AS ENUM ('clean', 'suspicious', 'infected', 'error', 'timeout', 'unknown');
  END IF;
END$$;

-- 1) dimension table: repositories
CREATE TABLE repositories (
  repo_id         BIGSERIAL PRIMARY KEY,
  repo_name       TEXT NOT NULL UNIQUE,          -- e.g. "owner/repo"
  first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_checked_at TIMESTAMPTZ                     -- updated by app or trigger
);

-- 2) hypertable: repo check log (when the repo was scanned/checked)
CREATE TABLE repo_log (
  checked_at  TIMESTAMPTZ NOT NULL,
  repo_id     BIGINT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
  notes       TEXT,                               -- optional: status/metadata about the check
  -- dedupe guard: one entry per repo per instant (tune if you want higher frequency)
  CONSTRAINT repo_log_unique UNIQUE (repo_id, checked_at)
);
SELECT create_hypertable('repo_log', 'checked_at', if_not_exists => TRUE);

-- 3) hypertable: file scan log (core of your app)
-- vt_counts example format:
-- {'malicious': 0, 'suspicious': 0, 'undetected': 62, 'harmless': 0, 'timeout': 0, 'confirmed-timeout': 0, 'failure': 0, 'type-unsupported': 14}
CREATE TABLE scan_log (
  checked_at       TIMESTAMPTZ NOT NULL, -- time the file scan finished (hypertable time column)
  repo_id          BIGINT NOT NULL REFERENCES repositories(repo_id) ON DELETE CASCADE,
  file_path        TEXT NOT NULL,        -- path or name relative to repo
  vt_counts        JSONB,                -- VirusTotal counts (can be NULL if VT timed out)
  vt_requested     BOOLEAN NOT NULL DEFAULT TRUE,   -- whether VT was attempted
  vt_error         TEXT,                              -- capture VT error/timeout reason if any

  clamav_threats   INT,                  -- # threats matched (null if not run)
  clamav_scantime_ms INT,                -- scan time in ms (or use INTERVAL if preferred)
  outcome          scan_outcome NOT NULL DEFAULT 'unknown',

  -- handy generated columns for fast filtering without JSON extraction
  vt_malicious     INT GENERATED ALWAYS AS ((vt_counts->>'malicious')::INT) STORED,
  vt_suspicious    INT GENERATED ALWAYS AS ((vt_counts->>'suspicious')::INT) STORED,
  vt_undetected    INT GENERATED ALWAYS AS ((vt_counts->>'undetected')::INT) STORED,
  vt_harmless      INT GENERATED ALWAYS AS ((vt_counts->>'harmless')::INT) STORED,
  vt_timeout       INT GENERATED ALWAYS AS (COALESCE((vt_counts->>'timeout')::INT, 0)) STORED,
  vt_confirmed_timeout INT GENERATED ALWAYS AS (COALESCE((vt_counts->>'confirmed-timeout')::INT, 0)) STORED,
  vt_failure       INT GENERATED ALWAYS AS (COALESCE((vt_counts->>'failure')::INT, 0)) STORED,
  vt_type_unsupported INT GENERATED ALWAYS AS (COALESCE((vt_counts->>'type-unsupported')::INT, 0)) STORED,

  -- optional: aggregate measure to score risk
  vt_total_detections INT GENERATED ALWAYS AS (
    COALESCE((vt_counts->>'malicious')::INT, 0) + COALESCE((vt_counts->>'suspicious')::INT, 0)
  ) STORED,

  -- dedupe/ordering helpers
  sha256           TEXT,                 -- if you hash files, index this
  scanner_version  TEXT,                 -- optional provenance
  metadata         JSONB,                -- anything else

  -- ensure we don't accidentally store duplicate rows for same file check instant
  CONSTRAINT scan_log_unique UNIQUE (repo_id, file_path, checked_at)
);
SELECT create_hypertable('scan_log', 'checked_at', if_not_exists => TRUE);

-- =========================
-- Indexes (critical for perf)
-- =========================

-- repositories
CREATE INDEX ON repositories (last_checked_at DESC);

-- repo_log
CREATE INDEX ON repo_log (repo_id, checked_at DESC);

-- scan_log: common filters
CREATE INDEX ON scan_log (repo_id, checked_at DESC);
CREATE INDEX ON scan_log (checked_at DESC);
CREATE INDEX ON scan_log (outcome, checked_at DESC);
CREATE INDEX ON scan_log (vt_malicious DESC, checked_at DESC);
CREATE INDEX ON scan_log (file_path);
CREATE INDEX ON scan_log (sha256) WHERE sha256 IS NOT NULL;

-- JSONB key lookup, if you expect ad-hoc queries on vt_counts
CREATE INDEX scan_log_vt_gin ON scan_log USING GIN (vt_counts);

-- fast fetch latest result per file in a repo
-- (supports DISTINCT ON queries or can use a lateral join)
CREATE INDEX ON scan_log (repo_id, file_path, checked_at DESC);

-- ===================================
-- Optional: keep repositories.updated
-- ===================================
CREATE OR REPLACE FUNCTION bump_last_checked()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
  UPDATE repositories
     SET last_checked_at = GREATEST(COALESCE(last_checked_at, '-infinity'::timestamptz), NEW.checked_at)
   WHERE repo_id = NEW.repo_id;
  RETURN NEW;
END$$;

CREATE TRIGGER scan_log_touch_repo
AFTER INSERT ON scan_log
FOR EACH ROW EXECUTE FUNCTION bump_last_checked();

CREATE TRIGGER repo_log_touch_repo
AFTER INSERT ON repo_log
FOR EACH ROW EXECUTE FUNCTION bump_last_checked();
--MUST RUN THIS SEPARATELY

CREATE MATERIALIZED VIEW daily_repo_risk
WITH (timescaledb.continuous) AS
SELECT
  time_bucket(INTERVAL '1 day', checked_at) AS day,
  repo_id,
  COUNT(*)                      AS files_scanned,
  SUM(COALESCE(vt_malicious,0)) AS vt_malicious_sum,
  SUM(COALESCE(vt_suspicious,0)) AS vt_suspicious_sum,
  SUM(CASE WHEN outcome IN ('infected','suspicious') THEN 1 ELSE 0 END) AS flagged_files,
  MAX(checked_at)               AS last_event
FROM scan_log
GROUP BY 1, 2;

-- refresh policy: fill 7 days back every 15 minutes
SELECT add_continuous_aggregate_policy('daily_repo_risk',
  start_offset => INTERVAL '7 days',
  end_offset   => INTERVAL '15 minutes',
  schedule_interval => INTERVAL '15 minutes'
);