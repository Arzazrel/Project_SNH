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
    <link rel="stylesheet" href="css/style.css"> </head>
<body>
    <div class="margin-top-md">
        <div class="upload-container">
            <div class="repo-header text-center">
                <h2 class="section-title">Account Activation</h2>
                <p class="text-muted">Verification sequence resolution gateway.</p>
            </div>

            <?php if ($error): ?>
                <div class="alert alert-danger text-center">
                    <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
                </div>
            <?php else: ?>
                <div class="alert alert-success text-center">
                    <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
                </div>
            <?php endif; ?>

            <div class="text-center margin-top-md">
                <a href="login.php" class="btn btn-submit-green">Go to Login Screen</a>
            </div>
        </div>
    </div>
</body>
</html>
