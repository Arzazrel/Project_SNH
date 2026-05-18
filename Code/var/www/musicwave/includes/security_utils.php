<?php
/* 
 * SECURITY UTILITIES
 * Whitelisting, Null-byte removal, and input validation.
 */

require_once __DIR__ . '/logger_setup.php';

class SecurityUtils {

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
            $securityLogger->warning("Illegal characters detected in lyrics", ["input" => $text]);
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
            $securityLogger->warning("Invalid username format", ["input" => $username]);
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
            $securityLogger->warning("Invalid email format for username", ["email" => $email]);
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
		$securityLogger->warning("Password validation failed: invalid length", ["length" => $length]);
		return false;
	    }
	    /*
	    // 2. Regex per la complessità:
	    // (?=.*[a-z]) -> at least a lower case
	    // (?=.*[A-Z]) -> at least an upper case
	    // (?=.*\d)    -> at least one number
	    // (?=.*[\W_]) -> at least an special char (non alfanumerico)
	    if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$/', $password)) {
		global $securityLogger;
		$securityLogger->warning("Password validation failed: weak complexity");
		return false;
	    }*/

    	return true; // La password è valida
    }
    
}
?>
