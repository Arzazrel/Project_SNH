<?php
/**
 * ACCOUNT VERIFICATION CONTROLLER
 * Validates the single-use token from the user email link and activates the user account.
 */

require_once __DIR__ . '/../config/db_config.php';
require_once DIR_INCLUDES . 'db_connect.php';
require_once DIR_INCLUDES . 'logger_setup.php';
require_once DIR_INCLUDES . 'security_utils.php';
require_once DIR_VENDOR . 'autoload.php';

SecurityUtils::startSecureSession();
SecurityUtils::sendSecurityHeaders();

$message = "";
$error = false;

// Rate limit control (Prevents CPU-level application DoS/DB queries) use 'validate' action as a shared slot to block IPs abusing authentication/verification endpoints.
if (!SecurityUtils::checkRateLimit($conn, 'validate')) {
    global $securityLogger;
    $securityLogger->warning("Verification DoS block triggered (Rate limit exceeded)", ["ip" => $_SERVER['REMOTE_ADDR']]);
    header("HTTP/1.1 429 Too Many Requests");
    exit("Too many verification attempts. Please try again after 15 minutes.");
}

// Retrieves and syntactically validates the token passed via URL (?token=...)
$token = $_GET['token'] ?? '';

# validation of the token
if (empty($token) || !preg_match('/^[a-f0-9]{64}$/i', $token)) {
    $message = "Invalid or missing activation token link.";
    $error = true;
    global $securityLogger;
    $securityLogger->warning("Registration verification invalid or missing activation token.", ["ip" => $_SERVER['REMOTE_ADDR']]);
} else {

    // Query the database for a user with that specific token and who has not expired
    $stmt = $conn->prepare("SELECT id, username FROM users WHERE activation_token = ? AND status = 'pending' AND activation_expires > NOW()");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        $user_id = $user['id'];
        $username = $user['username'];

        // Activates the user's account, canceling the token (making it disposable)
        $update_stmt = $conn->prepare("UPDATE users SET status = 'active', activation_token = NULL, activation_expires = NULL WHERE id = ?");
        $update_stmt->bind_param("i", $user_id);
        
        if ($update_stmt->execute()) {
            global $accessLogger;
            $accessLogger->info("User email successfully verified and account activated", ["username" => $username, "user_id" => $user_id]);	// write access log
            $message = "Thank you, " . htmlspecialchars($username) . "! Your email has been verified. You can now log in.";
        } else {
            global $errorLogger;
            $errorLogger->error("Failed to update status for user during email verification", ["user_id" => $user_id]);				// write error log
            $message = "A technical database error occurred during activation. Please contact support.";
            $error = true;
        }
        $update_stmt->close();
    } else {
        // Failed, invalid/expired token"
        global $securityLogger;
        $securityLogger->warning("Failed email activation attempt with invalid/expired token", ["token" => $token, "ip" => $_SERVER['REMOTE_ADDR']]);
        $message = "The activation link is invalid, has already been used, or has expired (validity is 24 hours). Please register again.";
        $error = true;
    }
    $stmt->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <title>MusicWave - Email Verification</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f6f9; padding: 40px; text-align: center; }
        .message-container { background: #fff; padding: 40px; border-radius: 8px; max-width: 500px; margin: 0 auto; border: 1px solid #def2f1; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
        .status-msg { font-size: 1.2em; font-weight: bold; margin-bottom: 20px; }
        .status-success { color: #155724; }
        .status-danger { color: #721c24; }
        .btn-login { display: inline-block; padding: 10px 20px; background-color: #2b7a78; color: white; text-decoration: none; border-radius: 4px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="message-container">
        <h2>Account Activation</h2>
        <p class="status-msg <?php echo $error ? 'status-danger' : 'status-success'; ?>">
            <?php echo htmlspecialchars($message); ?>
        </p>
        
        <?php if (!$error): ?>
            <a href="login.php" class="btn-login">Go to Login</a>
        <?php else: ?>
            <a href="register.php" class="btn-login" style="background-color: #666;">Back to Registration</a>
        <?php endif; ?>
    </div>
</body>
</html>
