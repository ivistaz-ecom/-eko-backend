-- eKO Portal — MySQL 8 schema (same as the SQLAlchemy models; `python -m app.init_db` creates it too)
CREATE DATABASE IF NOT EXISTS eko_portal CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE eko_portal;

CREATE TABLE IF NOT EXISTS users (
  id              BIGINT AUTO_INCREMENT PRIMARY KEY,
  login_key       VARCHAR(64)  NOT NULL UNIQUE COMMENT 'Microsoft Entra object ID (oid) – immutable',
  tenant_id       VARCHAR(64)  NOT NULL,
  username        VARCHAR(255) NOT NULL UNIQUE COMMENT 'M365 user principal name',
  email           VARCHAR(255) NULL,
  name            VARCHAR(255) NOT NULL,
  phone           VARCHAR(50)  NULL,
  language        VARCHAR(10)  NULL COMMENT 'NULL until picked on first login',
  city            VARCHAR(120) NULL,
  department      VARCHAR(160) NULL,
  job_title       VARCHAR(160) NULL,
  photo_url       VARCHAR(500) NULL,
  role            ENUM('super_admin','admin','employee') NOT NULL DEFAULT 'employee',
  is_active       TINYINT(1)   NOT NULL DEFAULT 1,
  first_login_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_login_at   DATETIME     NULL,
  created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_sessions (
  id                BIGINT AUTO_INCREMENT PRIMARY KEY,
  token_hash        VARCHAR(64)  NOT NULL UNIQUE COMMENT 'SHA-256 of the cookie token',
  user_id           BIGINT       NOT NULL,
  remember          TINYINT(1)   NOT NULL DEFAULT 0,
  created_at        DATETIME     NOT NULL,
  last_activity_at  DATETIME     NOT NULL,
  expires_at        DATETIME     NULL,
  revoked_at        DATETIME     NULL,
  revoke_reason     VARCHAR(40)  NULL,
  ip_address        VARCHAR(64)  NULL,
  user_agent        VARCHAR(500) NULL,
  INDEX ix_user_sessions_user_id (user_id),
  CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS oauth_states (
  state       VARCHAR(128) PRIMARY KEY,
  flow_json   TEXT         NOT NULL,
  remember    TINYINT(1)   NOT NULL DEFAULT 0,
  next_path   VARCHAR(500) NULL,
  created_at  DATETIME     NOT NULL,
  expires_at  DATETIME     NOT NULL,
  INDEX ix_oauth_states_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_events (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id     BIGINT       NULL,
  email       VARCHAR(255) NULL,
  event       VARCHAR(40)  NOT NULL COMMENT 'login_success, login_failed, logout, idle_timeout, ...',
  detail      VARCHAR(500) NULL,
  ip_address  VARCHAR(64)  NULL,
  user_agent  VARCHAR(500) NULL,
  created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX ix_login_events_user_id (user_id),
  INDEX ix_login_events_created_at (created_at),
  CONSTRAINT fk_events_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Optional nightly cleanup (or run from cron):
-- DELETE FROM user_sessions WHERE revoked_at IS NOT NULL AND revoked_at < NOW() - INTERVAL 90 DAY;
-- DELETE FROM oauth_states  WHERE expires_at < NOW();
