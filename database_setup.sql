CREATE DATABASE IF NOT EXISTS cyber_db;
USE cyber_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    is_admin TINYINT(1) NOT NULL DEFAULT 0,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    is_blocked TINYINT(1) NOT NULL DEFAULT 0,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    must_change_password TINYINT(1) NOT NULL DEFAULT 0
);

DELIMITER //

CREATE PROCEDURE add_column_if_missing(
    IN table_name_value VARCHAR(64),
    IN column_name_value VARCHAR(64),
    IN column_definition_value VARCHAR(255)
)
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = table_name_value
          AND COLUMN_NAME = column_name_value
    ) THEN
        SET @sql = CONCAT('ALTER TABLE ', table_name_value, ' ADD COLUMN ', column_name_value, ' ', column_definition_value);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END//

DELIMITER ;

CALL add_column_if_missing('users', 'is_admin', 'TINYINT(1) NOT NULL DEFAULT 0');
CALL add_column_if_missing('users', 'role', 'VARCHAR(50) NOT NULL DEFAULT ''user''');
CALL add_column_if_missing('users', 'is_blocked', 'TINYINT(1) NOT NULL DEFAULT 0');
CALL add_column_if_missing('users', 'failed_login_attempts', 'INT NOT NULL DEFAULT 0');
CALL add_column_if_missing('users', 'locked_until', 'DATETIME NULL');
CALL add_column_if_missing('users', 'must_change_password', 'TINYINT(1) NOT NULL DEFAULT 0');

DROP PROCEDURE add_column_if_missing;

CREATE TABLE IF NOT EXISTS user_activity (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    ip_address VARCHAR(64),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_activity_username (username),
    INDEX idx_user_activity_created_at (created_at)
);

CREATE TABLE IF NOT EXISTS scan_reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    tool VARCHAR(100) NOT NULL,
    target VARCHAR(500),
    summary TEXT,
    result_json LONGTEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_scan_reports_username (username),
    INDEX idx_scan_reports_tool (tool),
    INDEX idx_scan_reports_created_at (created_at)
);
