<?php
/**
 * PASSWORD RESET CONTROLLER (ACTION)
 * Public page that verifies the secret token from the email and updates the password.
 * Protections: Token Hash Verification, Expiration Control, Strict Input Validation, Token Destruction.
 */

require_once __DIR__ . '/../config/db_config.php';
require_once DIR_INCLUDES . 'db_connect.php';
require_once DIR_INCLUDES . 'logger_setup.php';
require_once DIR_INCLUDES . 'security_utils.php';

SecurityUtils::startSecureSession();		// start secure session

// Redirect if the user is already logged in
if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");		// redirect to main page
    exit();
}

SecurityUtils::sendSecurityHeaders();		// security headers

// Rate limit control (Prevents CPU-level application DoS/DB queries) use 'validate' action as a shared slot to block IPs abusing authentication/verification endpoints.
if (!SecurityUtils::checkRateLimit($conn, 'validate')) {
    global $securityLogger;
    $securityLogger->warning("Verification reset password DoS block triggered (Rate limit exceeded)", ["ip" => $_SERVER['REMOTE_ADDR']]);
    header("HTTP/1.1 429 Too Many Requests");
    exit("Too many verification reset password attempts. Please try again after 15 minutes.");
}

$error_message = "";
$success_message = "";
$is_token_valid = false;
$user_id = null;

// Retrieves and syntactically validates the token passed via URL (?token=...)
$token_raw = $_GET['token'] ?? $_POST['token'] ?? '';

// - 1 - validation of the token -
if (empty($token_raw) || !preg_match('/^[a-f0-9]{64}$/', $token_raw)) {
    $error_message = "Invalid or expired recovery token.";
    global $securityLogger;
    $securityLogger->warning("Password reset invalid or missing activation token.", ["ip" => $_SERVER['REMOTE_ADDR']]);
} else {

    // calculate the SHA-256 hash of the passed token to match with the DB
    $token_hash = hash('sha256', $token_raw);
    $now = (new DateTime())->format('Y-m-d H:i:s');

    // find the user who owns the token that has not expired
    $stmt = $conn->prepare("SELECT id, username FROM users WHERE token_reset_hash = ? AND reset_expires_at > ? AND status = 'active'");
    $stmt->bind_param("ss", $token_hash, $now);
    $stmt->execute();
    $result = $stmt->get_result();
    $user = $result->fetch_assoc();
    $stmt->close();

    if ($user) {
        $is_token_valid = true;		// set valid tokens
        $user_id = $user['id'];		// set user_id
    } else {
    	global $securityLogger;
        $securityLogger->warning("Failed email activation attempt with invalid/expired token", ["token" => $token, "ip" => $_SERVER['REMOTE_ADDR']]);
        $error_message = "The change password link is invalid, has already been used, or has expired (validity is 15 minutes). Please retry again.";
    }
}

// - 2 - Managing the submission of the new password and rate limit check -
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $is_token_valid) {
    global $securityLogger, $accessLogger;

    // check presence and validity of the token. Use of hash_equals to prevent timing attack during string comparision (apply Costant-Time Comparison)
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $securityLogger->warning("Reset Password CSRF attempt blocked", ["ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);
        header("HTTP/1.1 403 Forbidden");
        exit("Security Error: Invalid or missing CSRF Token.");
    }	
    unset($_SESSION['csrf_token']);		// one-time use-> destroy the token immediately after verification to prevent reuse

    $password_new = $_POST['password_new'] ?? '';		// get psw
    $password_confirm = $_POST['password_confirm'] ?? '';	// get confirm psw
    $password_valid = SecurityUtils::validatePassword($password_new);

    // Password validation
    if (!$password_valid) {
        $error_message = "Password does not meet complexity requirements (Min 8 chars, max 72 chars, 1 uppercase, 1 lowercase, 1 number).";
    } elseif ($password_new !== $password_confirm) {
        $error_message = "Passwords do not match.";
    } else {
        // Generating the new secure hash using BCRYPT
        $new_password_hash = password_hash($password_new, PASSWORD_BCRYPT);

        // DB Update: Set the new password and RESET the token fields to destroy it (One-Time Use)
        $update_stmt = $conn->prepare("UPDATE users SET password_hash = ?, token_reset_hash = NULL, reset_expires_at = NULL, login_attempts = 0, lock_until = NULL WHERE id = ?");
        $update_stmt->bind_param("si", $new_password_hash, $user_id);
        
        if ($update_stmt->execute()) {
            $accessLogger->info("User password successfully reset via recovery token", ["user_id" => $user_id]);
            $success_message = "Your password has been successfully updated. You can now log in.";
            $is_token_valid = false; 		// Hide the input form
        } else {
            $securityLogger->critical("Failed database update during password reset", ["user_id" => $user_id]);
            $error_message = "An internal error occurred. Please try again later.";
        }
        $update_stmt->close();
    }
}

// Regenerates the anti-CSRF token for the password entry form. The first csrf_token is created in forgot_password.php
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <title>MusicWave - Reset Password</title>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="css/style.css"> </head>
<body>
    <div class="margin-top-md">
        <div class="upload-container">
            <div class="repo-header text-center">
                <h2 class="section-title">Update Password</h2>
                <p class="text-muted">Establish the alternative secret access keys.</p>
            </div>

            <?php if ($error_message): ?>
                <div class="alert alert-danger">
                    <?php echo htmlspecialchars($error_message, ENT_QUOTES, 'UTF-8'); ?>
                </div>
            <?php endif; ?>

            <?php if ($success_message): ?>
                <div class="alert alert-success">
                    <?php echo htmlspecialchars($success_message, ENT_QUOTES, 'UTF-8'); ?>
                </div>
                <div class="text-center margin-top-md">
                    <a href="login.php" class="btn btn-submit-green">Return to Authenticator</a>
                </div>
            <?php endif; ?>

            <?php if ($is_token_valid): ?>
                <form method="POST" action="reset_password.php">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                    <input type="hidden" name="token" value="<?php echo htmlspecialchars($token_raw, ENT_QUOTES, 'UTF-8'); ?>">

                    <div class="form-group">
                        <label for="password_new">New Password</label>
                        <input type="password" id="password_new" name="password_new" class="form-control" required>
                        <span class="help-text">
                            Minimum 8 characters. Must contain at least one uppercase letter, one lowercase letter, and one numeric character.
                        </span>
                    </div>

                    <div class="form-group">
                        <label for="password_confirm">Confirm New Password</label>
                        <input type="password" id="password_confirm" name="password_confirm" class="form-control" required>
                    </div>
                    
                    <button type="submit" class="btn btn-submit-green">Update Password</button>
                </form>
            <?php elseif (!$success_message): ?>
                <div class="text-center margin-top-md">
                    <a href="forgot_password.php" class="page-link">Request a new reset link</a>
                </div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
