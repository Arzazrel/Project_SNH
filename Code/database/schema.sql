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
    reset_token VARCHAR(64) DEFAULT NULL,
    reset_token_expiration TIMESTAMP NULL DEFAULT NULL,
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

-- Audit Logs table for post-incident investigation
CREATE TABLE IF NOT EXISTS audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT DEFAULT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    severity ENUM('info', 'warning', 'critical') DEFAULT 'info',
    action VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Entering test users (Passwords: 'admin', 'user', 'prem_user')
-- Hashes are generated with BCRYPT (PASSWORD_DEFAULT in PHP)
--INSERT INTO users (username, password_hash, email, role) VALUES 
--('admin', '$2y$10$mC7p0pAnW9.Y9oK6N.hSre1a9Gv.D2v.H6qP4qP4qP4qP4qP4qP4q', 'admin@musicwave.it', 'admin'),
--('user', '$2y$10$mC7p0pAnW9.Y9oK6N.hSre1a9Gv.D2v.H6qP4qP4qP4qP4qP4qP4q', 'user@musicwave.it', 'standard'),
--('prem_user', '$2y$10$mC7p0pAnW9.Y9oK6N.hSre1a9Gv.D2v.H6qP4qP4qP4qP4qP4qP4q', 'premium@musicwave.it', 'premium');
