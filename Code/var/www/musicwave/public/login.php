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

SecurityUtils::startSecureSession();		// start secure session

// Redirect if the user is already logged in
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit();
}

SecurityUtils::sendSecurityHeaders();		// security headers

// Generate an Anti-CSRF token specifically for the Guest registration form if not already present
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error_message = "";		// var contanining the text for the error mex

// dynamically detects the best algorithm supported by the server (argon2d or BCRYP). For compatibility purpouse BCRYPT is default version.
$best_algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
// decoy constant: a valid but generic BCRYPT hash (matches the string 'dummy') used to waste CPU time when the real user is not present or is blocked
$dummy_bcrypt = '$2y$10$abcdefghijklmnopqrstuvwx23456789012345678901234567890';
$dummy_argon2id = '$argon2id$v=19$m=65536,t=4,p=1$bXpScWJpY0oxR0YwTkE$bXpScWJpY0oxR0YwTkFtelJxYmljSDFHMTBOQW16UnE';

// dynamically selects the dummy hash based on what the server uses as default
$dummy_hash = ($best_algo === PASSWORD_ARGON2ID) ? $dummy_argon2id : $dummy_bcrypt;

// Handle the POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // check presence and validity of the token. Use of hash_equals to prevent timing attack during string comparision (apply Costant-Time Comparison)
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        global $securityLogger;
    	$securityLogger->warning("Login CSRF attempt blocked", ["ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);		// write in security log
    	header("HTTP/1.1 403 Forbidden");			// redirect ot an error page to visualize the attack for the user
    	exit("Security Error: Invalid or missing CSRF Token.");
    }
    // regenerate a new anti-CSRF token for the form in case the page is reloaded with errors.
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    
    // rate limiting control (Protection against application-level DoS attacks on the CPU and Mail Flooding)
    if (!SecurityUtils::checkRateLimit($conn, 'login')) {
        global $securityLogger;
        $securityLogger->warning("Login DoS block triggered (Rate limit exceeded for IP)", ["ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);
        header("HTTP/1.1 429 Too Many Requests");							// redirect ot an error page to visualize the attack for the user
        exit("Too many login attempts from this connection. Please try again after 15 minutes.");
    }
    
    $email_raw = SecurityUtils::sanitizeInput($_POST['email'] ?? '');	// Sanitize username in input (Null byte removal)
    $password_raw = $_POST['password'] ?? ''; 				// Don't sanitize passwords to avoid altering characters

    $email = SecurityUtils::validateEmail($email_raw);			// Validate email(username) format, return false if something is incorrect

    // check the result of the email validation
    if (!$email) {
        $securityLogger->warning("Login attempt with invalid email format", ["input" => $email_raw, "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);	// set log
        $error_message = "Invalid credentials or account locked.";						// set error_mex
    } else {
        
        // Database operation with Prepared Statements, we fetch the password hash and lockout details
        $stmt = $conn->prepare("SELECT id, username, password_hash, status, login_attempts, lock_until, role FROM users WHERE email = ?");	// prepared query
        $stmt->bind_param("s", $email);			// put username into prepared query
        $stmt->execute();				// execute the query
        $result = $stmt->get_result();			// get results
        $user = $result->fetch_assoc();			// get first raw of the result
        $stmt->close();					// close connection

	// check, if the email is related to aregistered user
        if ($user) {	// - start - if 0 - [user found]
            # control for lock information
            $now = new DateTime();								// take current time
            $lock_until = $user['lock_until'] ? new DateTime($user['lock_until']) : null;	// if is blocked account take the time

            // check for Account Lockout
            if ($lock_until && $lock_until > $now) {	// - start - if 0.1 - [account locked]
                $securityLogger->warning("Login attempt on locked account", ["email" => $email, "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);	// write log
                $error_message = "Account temporarily locked. Please try again later.";			// set error_mex
                
            	password_verify($password_raw, $dummy_hash);	// ANTI-TIMING PROTECTION: run a dummy BCRYPT to simulate password checking time
            } 		// - end - if 0.1 -
            else {	// - start - else 0.1 - [account not locked]
                // Account is not blocked, now verify Password using BCRYPT
                // SUCCESS login
                if (password_verify($password_raw, $user['password_hash'])) {		// - start - if 0.1.1 - [correct password]
                    
                    // check pending status (Registered user but not activated via email)
                    if ($user['status'] === 'pending') {
                        $securityLogger->warning("Login blocked: Account registration is pending activation", ["email" => $email, "user_id" => $user['id'], "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);
                        $error_message = "Your account is not verified yet. Please check your inbox and click the activation link.";
                        
                        password_verify($password_raw, $dummy_hash); // ANTI-TIMING: eseguiamo comunque per simulare lo stesso tempo di elaborazione
                    } else {	// success login
                    
			SecurityUtils::resetRateLimitForIP($conn, 'login');	// Reset IP rate limit on successful login to prevent locking out NAT/Shared IPs
		    	
		    	SecurityUtils::rotateSessionId();			// rotate session ID to mitigate session fixation
		            
		        // dynamic rehash
		        if (password_needs_rehash($user['password_hash'], $best_algo)) {
                            
                            $new_hash = password_hash($password_raw, $best_algo);	// generate the new updated hash
                            
                            // reset the attempts AND update the hash in one go
                            $reset_stmt = $conn->prepare("UPDATE users SET login_attempts = 0, lock_until = NULL, password_hash = ? WHERE id = ?");
                            $reset_stmt->bind_param("si", $new_hash, $user['id']);
                            
                            $securityLogger->info("User password hash successfully upgraded to current server standard", ["user_id" => $user['id']]);
                        } else {
                            // don't change hash alg.
                            $reset_stmt = $conn->prepare("UPDATE users SET login_attempts = 0, lock_until = NULL WHERE id = ?");
                            $reset_stmt->bind_param("i", $user['id']);
                        }
		        
		        // reset attempts and set session
		        $reset_stmt->execute();
		        $reset_stmt->close();

		        $_SESSION['user_id'] = $user['id'];		// set user_id
		        $_SESSION['email'] = $email;			// set email
		        $_SESSION['username'] = $user['username'];	// set username
		        $_SESSION['last_access'] = time(); 		// set initial time for timeout tracking
		        $_SESSION['role'] = $user['role'];		// set the role of the user ('standard' or 'premium' or 'admin')
		           
		        // role-basedrouting control
		        if ($_SESSION['role'] === 'admin') {
			    $securityLogger->info("Admin user logged in, redirecting to admin dashboard", ["user_id" => $user['id'], "email" => $email, "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);		// write log
			    header("Location: admin_dashboard.php");
			    exit();
			} else {
			    $securityLogger->info("Standard/Premium user logged in, redirecting to user dashboard", ["user_id" => $user['id'], "email" => $email, "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);	// write log
			    header("Location: dashboard.php");
			    exit();
			}
		    }
                } 		// - end - if 0.1.1 - [correct password]
                // - start - esle 0.1.1 - [not correct password]
                else {			// NOT SUCCESS login, user insert incorrect psw
                
		    // Case in which the account lockout time has expired but the number of attempts is high. This allows the user to have three clean attempts again.
		    if ($lock_until) {
			$user['login_attempts'] = 0;		// reset the value of attempt
    		    } 
                
                    // FAILURE: Increment attempts and handle locking
                    $new_attempts = $user['login_attempts'] + 1;						 		// update the number of the attempt (manage server side)
                    $new_lock = null;

		    $securityLogger->warning("Failed login attempt", ["email" => $email, "attempt_no" => $new_attempts, "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);	// write log
                    $error_message = "Invalid credentials or account locked.";							// set error mex

		    // check if has reached the maximum number of attempts.
                    if ($new_attempts >= MAX_LOGIN_ATTEMPTS) {
                        $new_lock = (new DateTime())->modify('+' . LOCKOUT_TIME_MINUTES . ' minutes')->format('Y-m-d H:i:s');	// set new lockout time
                        $securityLogger->critical("Account locked: too many failed attempts", ["username" => $email, "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']); 		// write log
                    }

                    $update_stmt = $conn->prepare("UPDATE users SET login_attempts = ?, lock_until = ? WHERE id = ?");		// prepared query for update lock for the user
                    $update_stmt->bind_param("isi", $new_attempts, $new_lock, $user['id']);
                    $update_stmt->execute();
                    $update_stmt->close();
                }		// - end - esle 0.1.1 - [not correct password]
            }		// - end - else 0.1 - [account not locked]
        // - end - if 0 - [user found]
        } else {	// - start - else 0 - [user not found]
            // User not found: log it but show generic error to prevent User Enumeration
            $securityLogger->warning("Login attempt for non-existent user", ["email" => $email, "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);		// write log
            $error_message = "Invalid credentials or account locked.";						// set error mex
            
            password_verify($password_raw, $dummy_hash);	// ANTI-TIMING PROTECTION: run a dummy BCRYPT to simulate password checking time
        }		// - end - else 0 - [user not found]
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MusicWave - Login</title>
    <link rel="stylesheet" href="<?php echo defined('WEB_CSS') ? WEB_CSS : 'css/'; ?>style.css">
</head>
<body>

    <div class="auth-wrapper">
        <div class="auth-container">
            
            <div class="auth-header">
                <h2>Login to MusicWave</h2>
                <p>Welcome back! Please enter your credentials to access your dashboard.</p>
            </div>
            
            <?php if ($error_message): ?>
                <div class="alert alert-danger">
                    <?php echo htmlspecialchars($error_message); ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="login.php">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                
                <div class="form-group text-left">
                    <label for="email">Email Address</label>
                    <input type="email" id="email" name="email" class="form-control" required>
                </div>
                
                <div class="form-group text-left">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" class="form-control" required>
                </div>
                
                <button type="submit" class="btn btn-submit-green" style="margin-top: 15px;">Login</button>
            </form>
            
            <div class="footer-links">
                <p><a href="forgot_password.php">Forgot your password? Click here to recover it.</a></p>
                <p style="margin-top: 10px;"><a href="register.php">« Don't have an account? Register here.</a></p>
            </div>
            
        </div>
    </div>

</body>
</html>
