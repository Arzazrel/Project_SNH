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
    	// check if the input is an array
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeInput'], $data);	// (e.g., a form with checkboxes or multiple fields) apply the function recursively to each element of the array.
        }
        
        $data = str_replace(chr(0), '', $data);		// Remove Null Byte (0x00)
        return trim($data);				// Removes blank spaces, tabs, or line breaks at the beginning and end of the string.
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
     * Email validation for username.
     * Logs a warning if the format is invalid.
     */
    public static function validateEmail($email) {
        $email = self::sanitizeInput($email);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            global $securityLogger;
            $securityLogger->warning("Invalid email format for username", ["email" => $email]);
            return false;
        }
        return $email;
    }
}
?>
