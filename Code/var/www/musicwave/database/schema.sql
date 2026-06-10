-- Creation DB
CREATE DATABASE IF NOT EXISTS music_wave_DB;
USE music_wave_DB;

-- User table (with Soft Delete and Reset Password fields)
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    role ENUM('standard', 'premium', 'admin') DEFAULT 'standard',
    status ENUM('pending', 'active') DEFAULT 'pending',             -- activation status
    activation_token VARCHAR(64) DEFAULT NULL,                      -- single use secret
    activation_expires TIMESTAMP NULL DEFAULT NULL,                 -- Activation token expiration
    token_reset_hash VARCHAR(64) DEFAULT NULL,
    reset_expires_at TIMESTAMP NULL DEFAULT NULL,
    login_attempts INT DEFAULT 0,
    lock_until TIMESTAMP NULL DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP NULL DEFAULT NULL
);

-- Media table (Lyrics and Audio)
CREATE TABLE IF NOT EXISTS media (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(100) NOT NULL,
    author VARCHAR(100),
    type ENUM('lyrics', 'audio') NOT NULL,
    content TEXT NOT NULL, -- Text for lyrics or relative path for audio
    is_premium BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

ALTER TABLE media ADD CONSTRAINT unique_song_lyrics UNIQUE (title, author);	-- to prevent duplicate

-- Table optimized for IP-based rate limiting (used to limit registration requests)
CREATE TABLE IF NOT EXISTS rate_limits (
    ip_address VARCHAR(45) NOT NULL,
    action_type ENUM('registration', 'validate','login','password_recovery') NOT NULL,
    attempt_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ip_address, action_type, attempt_timestamp)
);

-- Entering test users (Passwords: 'admin', 'user', 'prem_user')
-- Hashes are generated with BCRYPT (PASSWORD_DEFAULT in PHP)
INSERT INTO users (username, password_hash, email, role, status) VALUES 
('admin', '$2y$10$I1Stow1gg43UQGF9cL9msuL/ofR6GTmmsGbMp4p9J3zbssr8YmTEK', 'admin@musicwave.it', 'admin', 'active'),
('user', '$2y$10$6gdXg2PPHubCSh2VqD0mT.yUtDF1dn6wi8T/aFTpIZxwIVmFVkQZ2', 'user@musicwave.it', 'standard', 'active'),
('prem_user', '$2y$10$AQ7xugkO8XtX3GigSjcl4.27wvPVtM7H6mFy79HibrCHD3o6F2Cai', 'premium@musicwave.it', 'premium', 'active');

-- password is: 'PasswordTester2026!'
INSERT INTO users (username, email, password_hash, status, role) VALUES 
('tester', 'tester@musicwave.it', '$2y$10$7R4MvEunI9pYbeGq9K3ySeYV1N7rPWhvO26/nN2mSGe28lY4wYRyO', 'active', 'premium');

-- Insert first lyrics (standard, visible to all)
INSERT INTO media (user_id, title, author, type, content, is_premium, created_at) VALUES 
(1, 'Lyrics Not Premium', 'The tester', 'lyrics','Walking through the lines of midnight,\nSearching for the bracket that I lost.\nThe server hums a song of daylight,\nCompiling dreams at any cost.\nOh, database, hear my prayer tonight!', 0,'2026-06-09 22:05:00'),
-- Insert second lyrics (premium, visible only for premium user)
(1, 'Lyrics Premium', 'The tester', 'lyrics','This is a premium lyrics! Reserved only for upgraded accounts.', 1, '2026-06-09 22:06:00'),
-- insert first audio (standard, visible to all) - already present in the public/uploads/audio folder
(1, 'Audio Not Premium', 'The tester', 'audio','uploads/audio/f75f80dfe53d7e7792fe75bfcace5a71_1781039508.mp3', 0, '2026-06-09 22:06:00'),
-- insert second audio (premium, visible only for premium user) - already present in the public/uploads/audio folder
(1, 'Audio Premium', 'The tester', 'audio','uploads/audio/903aa2d9fe9f9f32fec8af8879c04ef7_1781039706.mp3', 1, '2026-06-09 22:06:00');

-- Create a dedicated user with limited privileges
-- In a real scenario, change 'StrongPassword123!' to a secure secret
CREATE USER IF NOT EXISTS 'musicwave_user'@'localhost' IDENTIFIED BY 'StrongPassword123!';
-- Grant DML (Data Manipulation Language) permissions only
GRANT SELECT, INSERT, UPDATE, DELETE ON music_wave_DB.* TO 'musicwave_user'@'localhost';

-- Enable the Event Scheduler in the MariaDB engine
SET GLOBAL event_scheduler = ON;

DELIMITER $$
-- Create a cyclic event that cleans up expired pending records every hour
CREATE EVENT IF NOT EXISTS purge_expired_pending_users_and_log
ON SCHEDULE EVERY 1 HOUR
DO
BEGIN
    -- Delete rate limit attempts older than 15 minutes to save space
    DELETE FROM rate_limits 
    WHERE attempt_timestamp < NOW() - INTERVAL 15 MINUTE;

    -- Delete unconfirmed pending accounts within 24 hours.
    DELETE FROM users 
    WHERE status = 'pending' 
      AND created_at < NOW() - INTERVAL 1 DAY;
END$$
DELIMITER ;
