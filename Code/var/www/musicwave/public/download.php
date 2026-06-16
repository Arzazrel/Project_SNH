<?php
/**
 * SECURE DOWNLOAD GATEWAY CONTROLLER
 * Assures defense-in-depth against Path Traversal, BOLA/IDOR, and Cross-Site Request Forgery (CSRF).
 */

// load critical environmental parameters and configurations
require_once __DIR__ . '/../config/db_config.php';
require_once DIR_INCLUDES . 'db_connect.php';
require_once DIR_INCLUDES . 'logger_setup.php';
require_once DIR_INCLUDES . 'security_utils.php';

// initialize the isolated secure session mechanism
SecurityUtils::startSecureSession();

global $conn, $securityLogger;

// session Enforcement: Verify that the user is fully authenticated
if (!isset($_SESSION['user_id'])) {
    $securityLogger->warning("Unauthorized download initialization attempt rejected", ["user_id" => $_SESSION['user_id'] ?? 'ANONYMOUS', "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);
    header("HTTP/1.1 403 Forbidden");
    exit("Security Error: Authentication required.");
}

// Request Method Enforcement: Enforce POST method to prevent token leakages via GET parameter strings
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("HTTP/1.1 405 Method Not Allowed");
    header("Allow: POST");
    exit("Method Not Allowed.");
}

// anti-CSRF Protection: Check token existence and matching using constant-time comparison
$user_csrf_token = $_POST['csrf_token'] ?? '';
if (empty($user_csrf_token) || !hash_equals($_SESSION['csrf_token'] ?? '', $user_csrf_token)) {
    $securityLogger->warning("CSRF download interception triggered", ["user_id" => $_SESSION['user_id'] ?? 'ANONYMOUS', "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);
    header("HTTP/1.1 403 Forbidden");
    exit("Security Error: Invalid or missing CSRF token validation.");
}

// syntactic Input Validation: Force integer casting to prevent SQL Injection and arbitrary string injection.
$raw_id = isset($_POST['id']) ? trim((string)$_POST['id']) : '';	// Capture the raw parameter as a string if it exists adn '' if it is not exist
// control check if exist the parameter
if ($raw_id === '') {
    header("HTTP/1.1 400 Bad Request");
    exit("Invalid request: Missing identifier.");
}

// Tthere is the parameter, than validate it.
// ctype_digit() checks if all characters in the string are legal numerical digits. If it returns false, the input contains letters, spaces, or SQL injection characters (e.g., "1 OR 1=1").
if (!ctype_digit($raw_id)) {
    // Log the exact malicious payload string inside your security context before it gets destroyed
    $securityLogger->warning("Potential SQL Injection or parameter tampering detected in ID field", ["user_id" => $_SESSION['user_id'] ?? 'ANONYMOUS',"submitted_payload" => $raw_id, "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);
    header("HTTP/1.1 400 Bad Request");
    exit("Invalid request parameter processing.");
}

// Since we certified that the string contains ONLY numbers, casting is now safe, cast to int.
$file_id = (int)$raw_id;
// id value control check, id must be positive
if ($file_id <= 0) {
    header("HTTP/1.1 400 Bad Request");
    exit("Invalid request parameter processing.");
}

// establish session variables for authorization matrix mapping
$user_role = $_SESSION['role'] ?? 'standard';
$is_premium_user = ($user_role === 'premium');

// resource Retrieval: Query database using prepared statements to map metadata. The app relies on the 'media' table structure matching the query logic from audio_panel.php
$stmt = $conn->prepare("SELECT title, content, is_premium FROM media WHERE id = ? AND type = 'audio'");
$stmt->bind_param("i", $file_id);
$stmt->execute();
$audio_asset = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$audio_asset) {
    header("HTTP/1.1 404 Not Found");
    exit("The requested asset context does not exist.");
}

// BOLA/IDOR Containment: Ensure a standard user cannot download premium assets
if ((int)$audio_asset['is_premium'] === 1 && !$is_premium_user) {
    $securityLogger->warning("IDOR/BOLA premium download violation intercepted", ["user_id" => $_SESSION['user_id'] ?? 'ANONYMOUS', "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP', "compromised_asset_id" => $file_id]);
    header("HTTP/1.1 403 Forbidden");
    exit("Security Error: Premium privileges are required to download this asset.");
}

// path traversal Ccountermeasure: extract strict filename and anchor directory path on server
$isolated_filename = basename($audio_asset['content']);			// strips out any path or relative path entered in the string, keeping only the final file name
// canonical path resolution via OS Kernel: resolve both the target directory and the final destination path to their absolute canonical forms.
// realpath() strips out all symbolic links, relative directory structures (/./, /../), and returns the actual, definitive physical path on the storage disk.
$canonical_upload_dir = realpath(DIR_UPLOADS_AUDIO);			// upload directory path
$real_path = realpath(DIR_UPLOADS_AUDIO . $isolated_filename);		// media file path


// confinement validation: SEE NOTE 0
if ($real_path === false || strpos($real_path, $canonical_upload_dir) !== 0) {
    
    // Log a high-severity incident with contextual threat metadata for forensic auditing
    $securityLogger->critical("Path confinement breach attempted", ["user_id" => $_SESSION['user_id'] ?? 'ANONYMOUS', "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP', "injected_path" => $audio_asset['content']]);
    
    // Terminate execution and drop the connection with a generic secure error matrix
    header("HTTP/1.1 403 Forbidden");
    exit("Security Error: Path restriction violation.");
}

$absolute_storage_path = $real_path;		// safe trasmission: send the path in the chosen folder

// physical check on disk before launching download pipe stream
if (!file_exists($absolute_storage_path)) {
    $securityLogger->critical("Database mapping error: File registered but missing from storage disk", ["file_path" => $absolute_storage_path, "user_id" => $_SESSION['user_id'] ?? 'ANONYMOUS', "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);
    header("HTTP/1.1 404 Not Found");
    exit("The target binary asset could not be located on disk.");
}

// dynamic Renaming Engine: Clean user title to serve it as a safe download name. Replaces non-alphanumeric characters with underscores to prevent Injection
$clean_title = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $audio_asset['title']);
if (empty($clean_title)) {
    $clean_title = "download_track";
}
$user_visible_download_name = $clean_title . ".mp3";	// by constraint the files are with .mp3 extension only

// clear any output buffer to ensure binary file integrity
if (ob_get_level()) {
    ob_end_clean();
}

// transmission Stream Deployment: Enforce binary attachment download behavior headers
header('Content-Description: File Transfer');		// the current HTTP response is a file transfer.
header('Content-Type: audio/mpeg'); 			// explicitly instruct the browser that this is a binary MP3 stream, an audio not other type like script
header('Content-Disposition: attachment; filename="' . $user_visible_download_name . '"');	// forces local download using the sanitized database Title
header('Content-Transfer-Encoding: binary');		// binary format
header('Expires: 0');					// don't save in cache, redownload whenever required
header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
header('Pragma: public');
header('Content-Length: ' . filesize($absolute_storage_path));	// Inform the browser the exact size of the file in bytes. This allows the browser to show the user a download progress bar and an estimated time remaining.

// securely read the file from server local space and flush it to the user client
readfile($absolute_storage_path);
exit();

/*
NOTE 0:
	Evaluate the system's absolute path layout to detect anomalies:
	- If realpath() returns false, the target asset does not exist or cannot be resolved on disk.
	- strpos($real_path, $canonical_upload_dir) !== 0 enforces a strict whitelist rule: the absolute resolved path MUST start exactly with the root upload directory string (Index Position 0).

	If an adversary executed a Second-Order Path Traversal (e.g., by commenting out basename() during tests and pulling '../../config/db_config.php' from the DB), realpath() expands this to 
	the absolute string '/var/www/musicwave/config/db_config.php'. Because this resolved string lacks the prefix '/var/www/musicwave/uploads/audio/', strpos() fails to find it at index 0, 
	triggering the security block.
*/
