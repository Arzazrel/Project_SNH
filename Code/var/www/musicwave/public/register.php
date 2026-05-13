<?php
/**
 * REGISTER CONTROLLER
 * Handles new user creation with secure hashing and input validation.
 */

require_once __DIR__ . '/../config/db_config.php';
require_once DIR_INCLUDES . 'db_connect.php';
require_once DIR_INCLUDES . 'logger_setup.php';
require_once DIR_INCLUDES . 'security_utils.php';

$message = "";
$error = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // Sanitize and Validate Inputs
    $email = SecurityUtils::validateEmail($_POST['email'] ?? '');	// if is not valid return false
    $username = trim($_POST['username'] ?? ''); 			// clean
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    // Check Requirements
    if (!$email) {
        $message = "Please provide a valid email address.";		// invalid email
        $error = true;
    } elseif (empty($username) || strlen($username) < 3) {
        $message = "Username must be at least 3 characters long.";	// username too small
        $error = true;
    } elseif (strlen($password) < 8) {
        $message = "Password must be at least 8 characters long.";	// psw too small
        $error = true;
    } elseif ($password !== $confirm_password) {
        $message = "Passwords do not match.";				// psw and confirm don't match
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
            $securityLogger->warning("Registration attempt with existing email", ["email" => $email, "username" => $username]);
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
</head>
<body>
    <h2>Create a MusicWave Account</h2>
    
    <?php if ($message): ?>
        <p style="color: <?php echo $error ? 'red' : 'green'; ?>;">
            <?php echo htmlspecialchars($message); ?>
        </p>
    <?php endif; ?>

    <form method="POST" action="register.php">
        <div>
            <label>Username (Visible to others):</label><br>
            <input type="text" name="username" value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>" required>
        </div>
        <br>
        <div>
            <label>Email Address:</label><br>
            <input type="email" name="email" value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>" required>
        </div>
        <br>
        <div>
            <label>Password (min. 8 chars):</label><br>
            <input type="password" name="password" required>
        </div>
        <br>
        <div>
            <label>Confirm Password:</label><br>
            <input type="password" name="confirm_password" required>
        </div>
        <br>
        <button type="submit">Register</button>
    </form>
    <p><a href="login.php">Already have an account? Login here.</a></p>
</body>
</html>
