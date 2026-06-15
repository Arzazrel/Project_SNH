<?php
/** 
 * GLOBAL DIRECTORY CONFIGURATION
 * This file defines the paths for the entire application.
 */

// Root of the entire project
define("DIR_BASE", realpath(__DIR__ . '/../') . '/');

// Private Folders (Not accessible via URL)
define("DIR_INCLUDES", DIR_BASE . 'includes/');	// utilities and other common code 
define("DIR_CONFIG", DIR_BASE . 'config/');	// Configuration files
define("DIR_DATABASE", DIR_BASE . 'database/'); // SQL script, initialization and backup (schema.sql)
define("DIR_VENDOR", DIR_BASE . 'vendor/');	// Monolog folder

// Public Folder (This is your Document Root in Apache, web root)
define("DIR_PUBLIC", DIR_BASE . 'public/');

// Security: Logs must be even further away or in a dedicated system path
define("DIR_LOGS", '/var/www/musicwave_logs/');

// Server absolute path for file uploads (used by PHP move_uploaded_file)
define('DIR_UPLOADS_AUDIO', DIR_BASE . 'stored_media/uploads/audio/');

/** 
 * DATABASE CREDENTIALS for the dedicated low-privileged user.
 * For security purpose this file should be stored outside the web root or protected.
 */

define('DB_HOST', 'localhost');
define('DB_NAME', 'music_wave_DB');
define('DB_USER', 'musicwave_user'); 		// dedicated user, NOT root
define('DB_PASS', 'StrongPassword123!'); 	// actual password set in MySQL

/**
 * Application Settings 
 */
define('MAX_LOGIN_ATTEMPTS', 3);
define('LOCKOUT_TIME_MINUTES', 15);

/**
 * Ingestion and Upload Restrictions
 */
define('MAX_LYRICS_LENGTH', 65535);          	// maximum characters for standard MySQL TEXT
define('MAX_TITLE_AUTHOR_LENGTH', 255);       	// maximum characters for standard MySQL TEXT
define('MAX_AUDIO_FILE_SIZE', 10485760);     	// 10 Megabytes in bytes (10 * 1024 * 1024)

/**
 * SMTP Mail Server Settings
 */
define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_PORT', 587); 				// standard port for TLS
define('SMTP_USER', 'project.SNH.26@gmail.com');
define('SMTP_PASS', 'wjtsolvwoeeuubmg'); 		// google account app password
define('MAIL_FROM_NAME', 'MusicWave Security Team');
define('BASE_URL', 'https://localhost/');				
?>
