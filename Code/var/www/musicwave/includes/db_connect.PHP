<?php
/* 
 * Database Connection Manager using MySQLi.
 * Handles secure connection and provides a safe interface for queries.
 */

require_once __DIR__ . '/../config/db_config.php';
require_once __DIR__ . '/logger_setup.php';

class Database {
    private $conn = null;

    public function __construct() {
        $this->connect();
    }

    /**
     * Opens a connection to the database using the defined constants.
     * Uses errorLogger for connection failures.
     */
    private function connect() {
        if ($this->conn === null) {
            
            $this->conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);	// Establishing connection, using value stored in db_config

            if ($this->conn->connect_error) {
                global $errorLogger;
                // Log critical system error
                $errorLogger->critical("Database connection failed", [
                    "error" => $this->conn->connect_error,
                    "host" => DB_HOST
                ]);

                // Generic message to prevent Information Leakage
                die("Technical error. Please try again later.");
            }
            
            // Set charset to utf8mb4 for full Unicode support and security -> Explicitly setting the character set prevents attacks based on character encoding.
            $this->conn->set_charset("utf8mb4");
            
            // use a try-catch to prevent MySQL server configuration issues from crashing the entire app
            try {
                // Force MySQL to use the Italian (Europe/Rome) time zone for the current session
	    $this->conn->query("SET time_zone = '+02:00';");
            } catch (Exception $e) {
                global $errorLogger;
                if ($errorLogger) {
                    $errorLogger->warning("Failed to set MySQL session time_zone", ["error" => $e->getMessage()]);	// write in error log
                }
            }
            
        }
    }

    /**
     * Returns the raw connection object for Prepared Statements.
     */
    public function getConnection() {
        return $this->conn;
    }

    /**
     * Safely closes the connection.
     */
    public function closeConnection() {
        if ($this->conn !== null) {
            $this->conn->close();
            $this->conn = null;
        }
    }
}

// Global instance to be used across the application
$db = new Database();
$conn = $db->getConnection();
?>
