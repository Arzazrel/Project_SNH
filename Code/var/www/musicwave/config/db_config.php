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

/** 
 * DATABASE CREDENTIALS for the dedicated low-privileged user.
 * For security purpose this file should be stored outside the web root or protected.
 */

define('DB_HOST', 'localhost');
define('DB_NAME', 'music_wave_DB');
define('DB_USER', 'musicwave_user'); 		// Dedicated user, NOT root
define('DB_PASS', 'StrongPassword123!'); 	// actual password set in MySQL

/**
 * Application Settings 
 */
define('MAX_LOGIN_ATTEMPTS', 3);
define('LOCKOUT_TIME_MINUTES', 15);
?>
