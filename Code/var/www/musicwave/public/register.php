<?php
/**
 * REGISTER CONTROLLER
 * Handles new user creation with secure hashing and input validation.
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

SecurityUtils::sendSecurityHeaders();		// security headerss

// vars initializations
$message = "";
$error = false;

// initialize empty variables in case of GET request (to prevent display errors)
$display_username = "";
$display_email = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
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

            // insert new user
            $stmt = $conn->prepare("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)");
            $stmt->bind_param("sss", $username, $email, $hashed_password);
		
	    // check success for register operation
            if ($stmt->execute()) {
                $message = "Registration successful! You can now login.";
                $accessLogger->info("New user registered", ["email" => $email, "username" => $username]);	// write logs
                
                SecurityUtils::rotateSessionId();	// rotate session ID to mitigate session fixation
                header("Location: login.php");		// redirect to login page
                exit();
            } else {
                $errorLogger->error("Failed to insert user into DB", ["error" => $conn->error]);		// write log
                $message = "A technical error occurred.";
                $error = true;
            }
        }
    }
    
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
