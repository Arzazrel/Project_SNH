<?php
/**
 * PASSWORD RECOVERY CONTROLLER (REQUEST)
 * Allows users to request a password reset link.
 * Protections: Rate Limiting, Anti-CSRF, Anti-User Enumeration, DB Protection.
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

$message = "";		// var contanining the text for the error mex

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    global $securityLogger;

    // check presence and validity of the token. Use of hash_equals to prevent timing attack during string comparision (apply Costant-Time Comparison)
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        global $securityLogger;
    	$securityLogger->warning("Login CSRF attempt blocked", ["ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);		// write in security log
    	header("HTTP/1.1 403 Forbidden");			// redirect ot an error page to visualize the attack for the user
    	exit("Security Error: Invalid or missing CSRF Token.");
    }
    unset($_SESSION['csrf_token']);		// one-time use-> destroy the token immediately after verification to prevent reuse

    // rate limiting control (Protection against application-level DoS attacks on the CPU and Mail Flooding)
    if (!SecurityUtils::checkRateLimit($conn, 'password_recovery')) {
        global $securityLogger;
        $securityLogger->warning("Password recovery DoS block triggered (Rate limit exceeded for IP)", ["ip" => $_SERVER['REMOTE_ADDR']]);
        header("HTTP/1.1 429 Too Many Requests");							// redirect ot an error page to visualize the attack for the user
        exit("Too many retrieval requests from this connection. Please try again after 15 minutes.");
    }
    
    $email_raw = SecurityUtils::sanitizeInput($_POST['email'] ?? '');	// Sanitize username in input (Null byte removal)
    $email = SecurityUtils::validateEmail($email_raw);

    // Messaggio fisso standard mostrato SEMPRE all'utente esterno
    $message = "If your email address is registered with our system, you'll soon receive a link to reset your password. Also check your spam folder.";

    if (!$email) {
        // If the email format is invalid, we log the anomaly but do not change the visible behavior
        $securityLogger->warning("Recovery attempt with invalid email format", ["input" => $email_raw, "ip" => $_SERVER['REMOTE_ADDR']]);
    } else {
        
        // Check user presence with Prepared Statement
        $stmt = $conn->prepare("SELECT id, username FROM users WHERE email = ? AND status = 'active'");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();

        if ($user) {
            // The user exists and is active. We're generating secure recovery parameters.
            $token_raw = bin2hex(random_bytes(32)); 	// Secure random token to put in URL link
            $token_hash = hash('sha256', $token_raw);  	// Hash to save in the database (Defense in Depth)
            
            // The token will expire strictly after 15 minutes (short expiration)
            $expiry = (new DateTime())->modify('+15 minutes')->format('Y-m-d H:i:s');

            // Saving token hash and expiration to DB
            $update_stmt = $conn->prepare("UPDATE users SET token_reset_hash = ?, reset_expires_at = ? WHERE id = ?");
            $update_stmt->bind_param("ssi", $token_hash, $expiry, $user['id']);
            $update_stmt->execute();
            $update_stmt->close();

            // Send the mail with PHPmailer via secure SMTP
            $mail = new PHPMailer(true);
            try {
            	// SMTP Server Configuration (Constants defined in db_config.php)
                $mail->isSMTP();
                $mail->Host       = SMTP_HOST;
                $mail->SMTPAuth   = true;
                $mail->Username   = SMTP_USER;
                $mail->Password   = SMTP_PASS; // App Password di Google a 16 caratteri
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
                $mail->Port       = SMTP_PORT;

                // Sender and Recipient
                $mail->setFrom(SMTP_USER, MAIL_FROM_NAME);
                $mail->addAddress($email, $user['username']);

                // Email content
                $mail->isHTML(true);
                $mail->Subject = "Password recover- MusicWave";
                    
                // build the secure link that points to reset_password.php
            	$reset_link = "https://" . $_SERVER['HTTP_HOST'] . "/reset_password.php?token=" . $token_raw;
       
            	$mail->Body = "Hello " . htmlspecialchars($user['username']) . ",\n\n" .
                              "You have requested a password reset on MusicWave.\n" .
                              "Click the following link to set a new password (the link is valid for 15 minutes):\n\n" .
                              "<a href=\"" . $reset_link . "\">" . $reset_link . "</a><br><br>\n" .
                              "If you did not request this reset, please ignore this email.";

                $mail->AltBody = "Recover password. Please copy and paste the following link into your browser to recover your password: " . $reset_link;

                $mail->send();
                    
                global $accessLogger;
                $accessLogger->info("Password recovery mail sent", ["email" => $email, "username" => $user['username']]);	// write access logs
                    
                SecurityUtils::rotateSessionId();	// rotate session ID to mitigate session fixation
                    
            } catch (Exception $e) {
		global $errorLogger;
                $errorLogger->error("Mailer Error. Password recovery rolled back.", ["error" => $mail->ErrorInfo]);
            }  
        } else {
            // L'utente non esiste. Logghiamo l'evento a fini di audit ma non mostriamo errori fuori.
            $securityLogger->notice("Password reset requested for non-existent or pending email", ["email" => $email, "ip" => $_SERVER['REMOTE_ADDR']]);
            
            // ANTI-TIMING: simulate a dummy cryptographic operation to make the execution time indistinguishable from the case where the user actually exists.
            hash('sha256', bin2hex(random_bytes(32)));
        }
    }
    
    // Rigenera il token CSRF per prevenire attacchi in caso di successivi refresh della pagina
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>

<!DOCTYPE html>
<html lang="it">
<head>
    <title>MusicWave - Recupero Password</title>
    <meta charset="UTF-8">
</head>
<body>
    <h2>Recupero Password</h2>
    
    <?php if ($message): ?>
        <p style="color: green; font-weight: bold;"><?php echo htmlspecialchars($message); ?></p>
    <?php endif; ?>

    <form method="POST" action="forgot_password.php">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        
        <div>
            <label>Inserisci la tua email di registrazione:</label><br>
            <input type="email" name="email" required style="width: 250px;">
        </div>
        <br>
        <button type="submit">Invia link di ripristino</button>
    </form>
    <br>
    <p><a href="login.php">Torna al Login</a></p>
</body>
</html>
