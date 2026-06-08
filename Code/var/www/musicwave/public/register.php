<?php
/**
 * REGISTER CONTROLLER
 * Handles new user creation with secure hashing and input validation.
 */

require_once __DIR__ . '/../config/db_config.php';
require_once DIR_INCLUDES . 'db_connect.php';
require_once DIR_INCLUDES . 'logger_setup.php';
require_once DIR_INCLUDES . 'security_utils.php';
// We include Composer's central autoloader (automatically loads Monolog and PHPMailer)
require_once DIR_VENDOR . 'autoload.php';

// import the necessary namespaces for PHPMailer
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

SecurityUtils::startSecureSession();		// start secure session

// Redirect if the user is already logged in
if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");		// redirect to main page
    exit();
}

SecurityUtils::sendSecurityHeaders();		// security headers

// Generate an Anti-CSRF token specifically for the Guest registration form if not already present
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// vars initializations
$message = "";
$error = false;

// initialize empty variables in case of GET request (to prevent display errors)
$display_username = "";
$display_email = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // check presence and validity of the token. Use of hash_equals to prevent timing attack during string comparision (apply Costant-Time Comparison)
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        global $securityLogger;
    	$securityLogger->warning("Guest CSRF registration attempt blocked", ["ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);		// write in security log
    	header("HTTP/1.1 403 Forbidden");			// redirect ot an error page to visualize the attack for the user
    	exit("Security Error: Invalid or missing CSRF Token.");
    }

    unset($_SESSION['csrf_token']);		// one-time use-> destroy the token immediately after verification to prevent reuse
    
    // RATE LIMITING CONTROL (Protection against application-level DoS attacks on the CPU and Mail Flooding)
    if (!SecurityUtils::checkRateLimit($conn, 'registration')) {
        global $securityLogger;
        $securityLogger->warning("Registration DoS block triggered (Rate limit exceeded)", ["ip" => $_SERVER['REMOTE_ADDR']]);		// write in security log
        header("HTTP/1.1 429 Too Many Requests");		// redirect ot an error page to visualize the attack for the user
        exit("Too many registration attempts. Please try again after 15 minutes.");
    }
    
    // -- Sanitize and Validate Inputs (use SecurityUtils class) --
    // keep a clean version to put back into the form in case of an error
    $display_username = SecurityUtils::sanitizeInput($_POST['username'] ?? '');
    $display_email = SecurityUtils::sanitizeInput($_POST['email'] ?? '');
    
    $email = SecurityUtils::validateEmail($_POST['email'] ?? '');		// if is not valid return false
    $username = SecurityUtils::validateUsername($_POST['username'] ?? '');	// clean and check the username, if is not valid return false
    
    // password check (max 72 chars, BCRYPT requirements)
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $password_valid = SecurityUtils::validatePassword($password);
    
    // Check Requirements
    if (!$email) {
        $message = "Please provide a valid email address (max 255 characters).";
        $error = true;
    } elseif (!$username) {
        $message = "Username must be between 3 and 20 characters and contain only letters, numbers, or underscores.";
        $error = true;
    } elseif (!$password_valid) {
        $message = "Password must be between 8 and 72 characters long.";
        $error = true;
    } elseif ($password !== $confirm_password) {
        $message = "Passwords do not match.";
        $error = true;
    } else {
        // input are ok -> check if user already exists
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ? OR username = ?");	// prepared query to search 
        $stmt->bind_param("ss", $email, $username);
        $stmt->execute();				
        // check if already exist the user
        if ($stmt->get_result()->num_rows > 0) {
            $message = "Email or Username already taken.";
            $error = true;
            $securityLogger->warning("Registration attempt with existing email", ["email" => $email, "username" => $username, "ip" => $_SERVER['REMOTE_ADDR']]);
        } else {
            // hash the password using BCRYPT (NEVER store passwords in plain text or using MD5/SHA1)
            $hashed_password = password_hash($password, PASSWORD_BCRYPT);
            
            // Generation of the one-time activation secret code (Activation Token)
            $activation_token = bin2hex(random_bytes(32));
            // Let's set the activation token expiration to +24 hours from now
            $expires_at = date('Y-m-d H:i:s', strtotime('+1 day'));
            $status = 'pending';

            // insert new user
            $stmt = $conn->prepare("INSERT INTO users (username, email, password_hash, status, activation_token, activation_expires) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("ssssss", $username, $email, $hashed_password, $status, $activation_token, $expires_at);
		
	    // check success for register operation
            if ($stmt->execute()) {
            
            	// sending real email with PHPmailer via secure SMTP
            	$mail = new PHPMailer(true);
                try {
                    // Configurazione del Server SMTP (Costanti definite in db_config.php)
                    $mail->isSMTP();
                    $mail->Host       = SMTP_HOST;
                    $mail->SMTPAuth   = true;
                    $mail->Username   = SMTP_USER;
                    $mail->Password   = SMTP_PASS; // App Password di Google a 16 caratteri
                    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
                    $mail->Port       = SMTP_PORT;

                    // Mittente e Destinatario
                    $mail->setFrom(SMTP_USER, MAIL_FROM_NAME);
                    $mail->addAddress($email, $username);

                    // Contenuto dell'email
                    $mail->isHTML(true);
                    $mail->Subject = 'Verify your MusicWave Account';
                    
                    // Link di attivazione puntato alla pagina pubblica verify.php
                    $activation_link = BASE_URL . "public/verify.php?token=" . $activation_token;
                    
                    $mail->Body    = "<h1>Welcome to MusicWave, " . htmlspecialchars($username) . "!</h1>
                                      <p>Please click the button below to verify your email address and activate your account:</p>
                                      <p><a href='" . $activation_link . "' style='display:inline-block; padding: 10px 20px; background-color: #2b7a78; color: white; text-decoration: none; border-radius: 5px; font-weight: bold;'>Verify Account</a></p>
                                      <p>This link will expire in 24 hours.</p>
                                      <p>If you did not request this registration, you can safely ignore this message.</p>";
                    
                    $mail->AltBody = "Welcome to MusicWave! Please copy and paste the following link into your browser to activate your account: " . $activation_link;

                    $mail->send();
                    
                    global $accessLogger;
                    $accessLogger->info("New user registered and verification mail sent", ["email" => $email, "username" => $username]);	// write access logs
                    $message = "Registration successful! Please check your mailbox to activate your account before attempting to log in.";
                    
                    // reset the fields to empty the graphic form in case of success
                    $display_username = "";
                    $display_email = "";
                    
                    SecurityUtils::rotateSessionId();	// rotate session ID to mitigate session fixation
                    
                } catch (Exception $e) {
                    // manual logical transaction (Rollback): If the email send fails, we delete the user from the DB to allow them to try again, avoiding leaving an orphaned 'pending' account.
                    $stmt_rollback = $conn->prepare("DELETE FROM users WHERE email = ?");
                    $stmt_rollback->bind_param("s", $email);
                    $stmt_rollback->execute();
                    $stmt_rollback->close();

                    global $errorLogger;
                    $errorLogger->error("Mailer Error. Registration rolled back.", ["error" => $mail->ErrorInfo]);
                    $message = "An error occurred while sending the verification email. Registration aborted. Please try again.";
                    $error = true;
                }
            } else {
                $errorLogger->error("Failed to insert user into DB", ["error" => $conn->error]);		// write log
                $message = "A technical error occurred.";
                $error = true;
            }
        }
        $stmt->close();
    }
    
    // regenerate a new anti-CSRF token for the form in case the page is reloaded with errors.
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <title>MusicWave - Register</title>
    <meta charset="UTF-8">
    <style>
        .form-group {
            margin-bottom: 15px;
        }
        .field-layout {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .input-field {
            width: 250px;
            padding: 5px;
        }
        .hint-text {
            font-size: 0.85em;
            color: #555;
            font-style: italic;
        }
        .hint-strong {
            color: #2b7a78;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <h2>Create a MusicWave Account</h2>
    
    <?php if ($message): ?>
        <p style="color: <?php echo $error ? 'red' : 'green'; ?>;">
            <?php echo htmlspecialchars($message); ?>
        </p>
    <?php endif; ?>

    <form method="POST" action="register.php" autocomplete="off">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        
        <div class="form-group">
            <label>Username (Visible to others):</label><br>
            <div class="field-layout">
                <input type="text" name="username" class="input-field" 
                       value="<?php echo htmlspecialchars($display_username ?? ''); ?>" 
                       maxlength="20" required>
                <span class="hint-text">3 to 20 characters. Only letters, numbers, and the underscore (_) are allowed. <br><strong>No spaces or special characters.</strong></span>
            </div>
        </div>

        <div class="form-group">
            <label>Email Address:</label><br>
            <div class="field-layout">
                <input type="email" name="email" class="input-field" 
                       value="<?php echo htmlspecialchars($display_email ?? ''); ?>" 
                       maxlength="255" required>
                <span class="hint-text">Please enter a valid email address. It will be used to log in and recover your account. (Max 255 characters)</span>
            </div>
        </div>

        <div class="form-group">
            <label>Password:</label><br>
            <div class="field-layout">
                <input type="password" name="password" class="input-field" maxlength="72" required>
                <span class="hint-text">Length: <span class="hint-strong">8 - 72 chars</span>.<br>
                Tip: To make it robust, include at least one capital letter, one number, and one symbol (e.g., @, #, !). Avoid common words.</span>
            </div>
        </div>

        <div class="form-group">
            <label>Confirm Password:</label><br>
            <div class="field-layout">
                <input type="password" name="confirm_password" class="input-field" maxlength="72" required>
                <span class="hint-text">Please retype the password you entered above to verify that it is correct.</span>
            </div>
        </div>

        <button type="submit" style="padding: 8px 15px; margin-top: 10px;">Register</button>
    </form>
    
    <p><a href="login.php">Already have an account? Login here.</a></p>
</body>
</html>
