<?php
/* 
 * SECURITY UTILITIES
 * Whitelisting, Null-byte removal, and input validation.
 */

require_once __DIR__ . '/logger_setup.php';

class SecurityUtils {

    /**
    * Sends secure HTTP headers to prevent Clickjacking, MIME-sniffing.
    * Should be called at the very beginning of every script.
    *
    * NOTE 0 - ("X-Frame-Options: DENY")
    * Mitigates: Clickjacking attacks
    * instructs browsers to completely block your web page from rendering inside an <frame> or <iframe> on any site—including your own domain, ensuring malicious sites cannot overlay or embed your content.
    *
    * NOTE 1 - ("X-Content-Type-Options: nosniff")
    * Mitigates: MIME-sniffing vulnerabilities and cross-site scripting (XSS)
    * Forces the browser to strictly adhere to the Content-Type header sent by the server, preventing it from executing non-executable files (like text or images) as scripts
    */
    public static function sendSecurityHeaders() {
    	if (!headers_sent()) {
    	    header("X-Frame-Options: DENY"); 			// SEE NOTE 0
	    header("X-Content-Type-Options: nosniff");		// SEE NOTE 1
	    header("Content-Type: text/html; charset=UTF-8");
	}
    }

    // --- INPUT SANITIZATION AND FILTERS ---

    /**
     * Removes null bytes and cleans input string/array recursively.
     * Prevents Null Byte Injection attacks.
     */
    public static function sanitizeInput($data) {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeInput'], $data);
        }
        // Remove Null Byte (0x00)
        $data = str_replace(chr(0), '', $data);
        return trim($data);
    }

    /**
     * Whitelist for Lyrics: Alphanumeric and basic punctuation only.
     * Logs a warning if illegal characters are detected.
     */
    public static function validateLyrics($text) {
        $clean = self::sanitizeInput($text);
        // RegEx whitelist
        if (!preg_match("/^[a-zA-Z0-9\s\.,!\?'\-]*$/", $clean)) {
            global $securityLogger;
            $securityLogger->warning("Illegal characters detected in lyrics", ["input" => $text, "ip" => $_SERVER['REMOTE_ADDR']]);
            return false; 
        }
        return $clean;
    }
    
    /**
     * Whitelist for Title and Author: Letters, numbers, spaces, hyphens, and apostrophes and round brackets only. Intended to allow only characters that make sense for titles and authors.
     * Specifically excludes semicolons (;), quotes ("), underscores (_), and SQL comments (--) to maintain data hygiene.
     */
    public static function validateMeta($string) {
        $clean = self::sanitizeInput($string);
    
        // Allow: letters (a-z, A-Z), numbers (0-9), spaces (\s), apostrophe ('), dash (\-), round brackets ()
        if (!preg_match("/^(?!.*--)[a-zA-Z0-9\s'\-\(\)]*$/", $clean)) {
            global $securityLogger;
            $securityLogger->warning("Suspicious characters detected in lyrics/song metadata", ["input" => $string, "ip" => $_SERVER['REMOTE_ADDR']]);	// write in the log
        return false;
    }
    return $clean;
}

    /**
     * Username validation 
     */
    public static function validateUsername($username) {
        $clean = self::sanitizeInput($username);
        // lenght 3-20, alphanumeric and underscore only
        if (!preg_match("/^[a-zA-Z0-9_]{3,20}$/", $clean)) {
            global $securityLogger;
            $securityLogger->warning("Invalid username format", ["input" => $username, "ip" => $_SERVER['REMOTE_ADDR']]);
            return false;
        }
        return $username;
    }

    /**
     * Email validation.
     * Logs a warning if the format is invalid.
     */
    public static function validateEmail($email) {
        $clean = self::sanitizeInput($email);
        if (strlen($clean) > 255 || !filter_var($clean, FILTER_VALIDATE_EMAIL)) {
            global $securityLogger;
            $securityLogger->warning("Invalid email format for username", ["email" => $clean, "ip" => $_SERVER['REMOTE_ADDR']]);
            return false;
        }
        return $email;
    }
    
    /**
     * Password validation. Use PHP PASSWORD_BCRYPT: password parameter being truncated to a maximum length of 72 bytes. 
     * First lenght check and then security level check. To achieve a strong password at least one uppercase, one lowercase, one number, and one special char.
     * Logs a warning if the format is invalid.
     */
    public static function validatePassword($password) {
    	// length check
	$length = strlen($password);
	if ($length < 8 || $length > 72) {
	    global $securityLogger;
	    $securityLogger->warning("Password validation failed: invalid length", ["length" => $length, "ip" => $_SERVER['REMOTE_ADDR']]);
	    return false;
	}
	    
	// Regex for password complexity check
	// (?=.*[a-z]) -> at least a lower case
	// (?=.*[A-Z]) -> at least an upper case
	// (?=.*\d)    -> at least one number
	// (?=.*[\W_]) -> at least an special char (non alfanumerico)
	if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$/', $password)) {
	    global $securityLogger;
	    $securityLogger->warning("Password validation failed: weak complexity");
	    return false;
	}

    	return true; // La password è valida
    }
    
    // --- SESSION MANAGEMENT ---

    /**
     * Starts a secure PHP session and checks for inactivity timeout.
     * Redirects to logout/login if the session has expired.
     */
    public static function startSecureSession() {
        // check if already exist a started or activated session
        if (session_status() === PHP_SESSION_NONE) {
            // there isn't a session, start a new session -> configuring session cookie parameters
            session_set_cookie_params([
                'lifetime' => 0,                      // Cookie expires when the browser closes (only in RAM)
                'path' => '/',                        // Valid for the entire application domain (in this project /public)
                'domain' => '',                       // Current host. The browser automatically assigns the cookie to the exact host that served the page (in this project localhost).
                'secure' => true,                     // to force https only
                'httponly' => true,                   // Mitigates XSS: Prevents JavaScript from reading the session token
                'samesite' => 'Strict'                // Mitigates CSRF: Restricts cross-site cookie transmission
            ]);

            session_start();	// start or restart session
        }

    	// there is an active session -> SESSION TIMEOUT LOGIC (10 Minutes)
    	$timeout_duration = 600; 	// 10 minutes * 60 seconds

	// check the last access time
        if (isset($_SESSION['last_access'])) {
            
            $session_age = time() - $_SESSION['last_access'];		// calculate session age
            if ($session_age > $timeout_duration) {
            	// session has expired, clear data and force logout
            	self::destroySession();
            	header("Location: login.php?error=timeout");
            	exit();
            }
        }
    
        // update last access time for active users (check if there is a session by 'user_id' field)
        if (isset($_SESSION['user_id'])) {
            $_SESSION['last_access'] = time();
        }
    }

    /**
     * Regenerates the session ID: generates a completely new and random PHPSESSID for the current user. The true parameter is to delete the old session file on the server.
     * Mitigates: Session Fixation attacks. An attacker takes a valid but not yet logged-in session ID and inserts it into the victim's browser via a malicious link. 
     * 		  If the victim enters their credentials and logs in using the ID, the attacker find themselves logged in as the victim. 
     * 		  By regenerating the ID immediately after logging in, the old ID becomes worthless, and the user receives a secure, secret token.
     */
    public static function rotateSessionId() {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);		// generate a new random session ID and delete the old server-side storage file
        }
     }

     /**
      * Fully destroys a session on both server-side and client-side (ex. Logout).
      * Used for: logout, session timeout (inactivity for 10 minutes), Security Anomaly Detected (session hijacking).
      */
     public static function destroySession() {
    	// check if there is a current session 
    	if (session_status() === PHP_SESSION_NONE) {
            session_start();				// start a session to destroy
        }

        $_SESSION = array();	// clear the server-side $_SESSION array, equal to session_unset. Free data from memory

     	// delete the session cookie from the client's browser
     	if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
                setcookie(
                    session_name(), 
            	    '', 
                    time() - 42000, 		// Backdate expiration time to force deletion
                    $params["path"], 
                    $params["domain"], 
                    $params["secure"], 
                    $params["httponly"]
            );
         }
         
    	session_destroy();		// destroy the session file on the server
    }
    
    /**
     * Checks whether an IP address has exceeded the maximum retry limit for a given action. If it hasn't passed it, log the current attempt.
     * @param mysqli $conn Connessione al database
     * @param string $action L'azione da controllare ('registration' o 'login')
     * @return bool True se l'accesso è consentito, False se l'IP è bloccato (Rate Limit superato)
     */
    public static function checkRateLimit(mysqli $conn, string $action): bool {
    	$ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
	    
	// Counts the attempts made by this IP in the last 15 minutes for this specific action
	$stmt = $conn->prepare("SELECT COUNT(*) FROM rate_limits WHERE ip_address = ? AND action_type = ? AND attempt_timestamp > NOW() - INTERVAL 15 MINUTE");
	$stmt->bind_param("ss", $ip, $action);
	$stmt->execute();
	$result = $stmt->get_result()->fetch_row();
	$attempts = $result[0];
	$stmt->close();

	// MAX_LOGIN_ATTEMPTS is defined in db_config.php and is equal to 3
	if ($attempts >= MAX_LOGIN_ATTEMPTS) {
	    return false; 				# block, too many attempts
	}

	// If it is below the limit, we record this new attempt in the table
	$stmt = $conn->prepare("INSERT INTO rate_limits (ip_address, action_type) VALUES (?, ?)");
	$stmt->bind_param("ss", $ip, $action);
	$stmt->execute();
	$stmt->close();

	return true; // Accesso consentito
    }
}
?>
