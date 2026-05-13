<?php
/**
 * LOGIN CONTROLLER
 * Handles user authentication, rate limiting, and security logging.
 * The error message is the same whether the user does not exist, the password is incorrect, or the account is locked to prevent an attacker from stealing information from failed attempts.
 */

// Load configuration and dependencies
require_once __DIR__ . '/../config/db_config.php';
require_once DIR_INCLUDES . 'db_connect.php';
require_once DIR_INCLUDES . 'logger_setup.php';
require_once DIR_INCLUDES . 'security_utils.php';

session_start();

// Redirect if already logged in
if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");		// redirect to main page
    exit();
}

$error_message = "";		// var contanining the text for the error mex

// Handle the POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    $email_raw = SecurityUtils::sanitizeInput($_POST['email'] ?? '');	// Sanitize username in input (Null byte removal)
    $password_raw = $_POST['password'] ?? ''; 				// Don't sanitize passwords to avoid altering characters

    $email = SecurityUtils::validateEmail($email_raw);			// Validate email(username) format, return false if something is incorrect

    // check the result of the email validation
    if (!$email) {
        $securityLogger->warning("Login attempt with invalid email format", ["input" => $email_raw]);	// set log
        $error_message = "Invalid credentials or account locked.";						// set error_mex
    } else {
        
        // Database operation with Prepared Statements, we fetch the password hash and lockout details
        $stmt = $conn->prepare("SELECT id, password_hash, login_attempts, lock_until FROM users WHERE email = ?");	// prepared query
        $stmt->bind_param("s", $email);			# put username into prepared query
        $stmt->execute();				# execute the query
        $result = $stmt->get_result();			# get results
        $user = $result->fetch_assoc();			# get first raw of the result

	// check 
        if ($user) {
            # control for lock information
            $now = new DateTime();								// take current time
            $lock_until = $user['lock_until'] ? new DateTime($user['lock_until']) : null;	// if is blocked account take the time

            // check for Account Lockout
            if ($lock_until && $lock_until > $now) {
                $securityLogger->warning("Login attempt on locked account", ["email" => $email]);	// write log
                $error_message = "Account temporarily locked. Please try again later.";			// set error_mex
            } 
            else {
                // Account is not blocked, now verify Password using BCRYPT
                if (password_verify($password_raw, $user['password_hash'])) {
                    
                    // SUCCESS: Reset attempts and set session
                    $reset_stmt = $conn->prepare("UPDATE users SET login_attempts = 0, lock_until = NULL WHERE id = ?");	// prepared query for update 
                    $reset_stmt->bind_param("i", $user['id']);
                    $reset_stmt->execute();

                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['email'] = $email;
                    
                    $accessLogger->info("User logged in successfully", ["user_id" => $user['id'], "email" => $email]);		// write log
                    
                    header("Location: dashboard.php");
                    exit();
                } 
                else {
                
		    // SE IL TEMPO È SCADUTO MA I TENTATIVI SONO ANCORA ALTI, RESETTIAMO IL CONTATORE
		    // Questo permette all'utente di avere di nuovo 3 tentativi puliti.
		    if ($lock_until && $lock_until <= $now) {
			$reset_attempts_stmt = $conn->prepare("UPDATE users SET login_attempts = 0, lock_until = NULL WHERE id = ?");
			$reset_attempts_stmt->bind_param("i", $user['id']);
			$reset_attempts_stmt->execute();
			$user['login_attempts'] = 0; // Aggiorniamo la variabile locale
    		    } 
                
               
                    // FAILURE: Increment attempts and handle locking
                    $new_attempts = $user['login_attempts'] + 1;								// update the number of the attempt (manage server side)s
                    $new_lock = null;

		    $securityLogger->warning("Failed login attempt", ["email" => $email, "attempt_no" => $new_attempts]);	// write log
                    $error_message = "Invalid credentials or account locked.";							// set error mex

		    // check if is
                    if ($new_attempts >= MAX_LOGIN_ATTEMPTS) {
                        $new_lock = (new DateTime())->modify('+' . LOCKOUT_TIME_MINUTES . ' minutes')->format('Y-m-d H:i:s');	// set new lockout time
                        $securityLogger->critical("Account locked: too many failed attempts", ["username" => $email]); 		// write log
                    }

                    $update_stmt = $conn->prepare("UPDATE users SET login_attempts = ?, lock_until = ? WHERE id = ?");		// prepared query for update lock for the user
                    $update_stmt->bind_param("isi", $new_attempts, $new_lock, $user['id']);
                    $update_stmt->execute();
                }
            }
        } else {
            // User not found: log it but show generic error to prevent User Enumeration
            $securityLogger->warning("Login attempt for non-existent user", ["email" => $email]);		// write log
            $error_message = "Invalid credentials or account locked.";						// set error mex
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <title>MusicWave - Login</title>
    <meta charset="UTF-8">
</head>
<body>
    <h2>Login to MusicWave</h2>
    
    <?php if ($error_message): ?>
        <p style="color: red;"><?php echo htmlspecialchars($error_message); ?></p>
    <?php endif; ?>

    <form method="POST" action="login.php">
        <div>
            <label>Email:</label><br>
            <input type="email" name="email" required>
        </div>
        <br>
        <div>
            <label>Password:</label><br>
            <input type="password" name="password" required>
        </div>
        <br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
