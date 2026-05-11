<?php
/** MONOLOG SETUP
 * I will use multiple different channels and multiple log files to logically separate the files.
 * This division will allow for separate and specific management of the various log types, allowing for comprehensive data collection for any scope.
 */

require_once __DIR__ . '/../vendor/autoload.php';

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Processor\WebProcessor;

// --- 1. SECURITY LOGGER --- SEE NOTE
$securityLogger = new Logger('security');
// Only logs WARNING and above to security.log
$securityLogger->pushHandler(new StreamHandler(DIR_LOGS . 'security.log', Logger::WARNING));	// minimum threshold is warning
$securityLogger->pushProcessor(new WebProcessor());

// --- 2. ACCESS/ACTIVITY LOGGER ---
$accessLogger = new Logger('activity');
// Logs INFO and above to access.log
$accessLogger->pushHandler(new StreamHandler(DIR_LOGS . 'access.log', Logger::INFO));		// minimum threshold is info
$accessLogger->pushProcessor(new WebProcessor());

// --- 3. SYSTEM ERROR LOGGER ---
$errorLogger = new Logger('system');
// Logs only ERROR and above to system_errors.log
$errorLogger->pushHandler(new StreamHandler(DIR_LOGS . 'system_errors.log', Logger::ERROR));	// minimum threshold is error
$errorLogger->pushProcessor(new WebProcessor());


/** NOTE and Examples of usage:
 * -- NOTE --
 *
 * - LOG LEVEL (from lower to higher) -> debug < info < notice < warning < error < critica < alert < emergency
 * 
 * - security -
 * Contents: Failed login attempts, locked accounts, SQL injection attempts detected, permission violations (Access Denied), CSRF attacks.
 * Levels used: WARNING, CRITICAL, ALERT.
 *
 * - activity -
 * Content: Successful logins, logout, song uploads, downloads, profile changes.
 * Levels used: INFO, NOTICE.
 *
 * - system -
 * Contents: PHP errors, database offline, email sending failure, filesystem errors.
 * Levels used: ERROR, CRITICAL.
 *
 * -- examples --
 * - security -
 * $securityLogger->warning("Failed login attempt", ["username" => $user_input]);
 * $securityLogger->critical("Account locked due to brute force protection", ["user" => $username]);
 * $securityLogger->alert("SQL Injection pattern detected in input", ["payload" => $input]);
 *
 * - activity -
 * $accessLogger->info("User logged in", ["id" => $_SESSION['user_id']]);
 * $accessLogger->notice("User changed their password", ["id" => $_SESSION['user_id']]);
 * $accessLogger->info("New song uploaded", ["title" => $song_name, "author" => $author]);
 *
 * - system -
 * $errorLogger->error("Failed to write temporary file to /tmp", ["file" => $temp_name]);
 * $errorLogger->critical("Database is DOWN", ["host" => DB_HOST, "error" => $conn->connect_error]);
 *
 */
?>
