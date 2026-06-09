<?php
/**
 * ADMINISTRATOR DASHBOARD CONTROLLER
 * Allows the administrator to promote users to Premium and demote them to Non-Premium.
 * Protections: Strict Authorization Check, Anti-CSRF on State Mutations, Prepared Statements, Audit Logging.
 */

require_once __DIR__ . '/../config/db_config.php';
require_once DIR_INCLUDES . 'db_connect.php';
require_once DIR_INCLUDES . 'logger_setup.php';
require_once DIR_INCLUDES . 'security_utils.php';
require_once DIR_VENDOR . 'autoload.php';

SecurityUtils::startSecureSession();		// start secure session

// Role Check - We verify that the user is logged in AND that his role in the session is strictly 'admin'
if (!isset($_SESSION['user_id']) || !isset($_SESSION['user_role']) || $_SESSION['user_role'] !== 'admin') {
    global $securityLogger;
    $securityLogger->warning("Unauthorized access attempt to admin dashboard", ["user_id" => $_SESSION['user_id'] ?? 'ANONYMOUS',"ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN']);	// write security log
    header("HTTP/1.1 403 Forbidden");								// redirect page
    exit("Security Error: Access Denied. You do not have permission to view this page.");
}

SecurityUtils::sendSecurityHeaders();		// security headers

// Generate an Anti-CSRF token specifically for the Guest registration form if not already present
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = "";
$error_message = "";

// management of State Change (Promotion / Degradation) via POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    global $securityLogger, $accessLogger;

    // check presence and validity of the token. Use of hash_equals to prevent timing attack during string comparision (apply Costant-Time Comparison)
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        global $securityLogger;
    	$securityLogger->warning("Admin CSRF attempt blocked on privilege modification", ["admin_id" => $_SESSION['user_id'], "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);		// write in security log
    	header("HTTP/1.1 403 Forbidden");			// redirect ot an error page to visualize the attack for the user
    	exit("Security Error: Invalid or missing CSRF Token.");
    }
    unset($_SESSION['csrf_token']);		// one-time use-> destroy the token immediately after verification to prevent reuse

    // Recovery and sanitization of operation inputs
    $target_user_id = filter_var($_POST['target_user_id'] ?? '', FILTER_VALIDATE_INT);	// get user_id
    $action = $_POST['action'] ?? '';							// get type of operation

    // control check for target user_id and opertion type
    if ($target_user_id === false || !in_array($action, ['make_premium', 'make_non_premium'])) {
        $error_message = "Invalid action parameters.";							// error
    } else {
        // 
        $new_role = ($action === 'make_premium') ? 'premium' : 'standard';

        // Additional security check to prevent admin from taking away privileges
        if ($target_user_id === $_SESSION['user_id']) {
            $error_message = "You cannot alter your own administrative privileges.";
        } else {
            // We perform the update on the DB with a Prepared Statement. Role values ('standard', 'premium', 'admin')
            $stmt = $conn->prepare("UPDATE users SET role = ? WHERE id = ? AND role != 'admin'");
            $stmt->bind_param("si", $new_role, $target_user_id);
            
            // update check
            if ($stmt->execute() && $stmt->affected_rows > 0) {							// update success
                $message = "User privilege updated successfully.";
                
                // Detailed action logging. An action that modifies privileges must be tracked at all times, not only for post-incident investigation purposes.
                $accessLogger->info("Administrator changed user privilege status", ["admin_id" => $_SESSION['user_id'],"target_user_id" => $target_user_id,"new_privilege" => $new_role,"ip" => $_SERVER['REMOTE_ADDR']]);
            } else {
                $error_message = "Failed to update privileges. User might not exist or is an admin.";		// update failed
            }
            $stmt->close();
        }
    }
    // regenerate a new anti-CSRF token for the form in case the page is reloaded with errors.
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Retrieve the list of users to display in the table (Prepared Statement without external dynamic parameters)
// We select only users with editable roles (we exclude other administrators for security reasons)
$query = "SELECT id, username, email, role, status FROM users WHERE role != 'admin' ORDER BY username ASC";
$result = $conn->query($query);
$users_list = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
?>

<!DOCTYPE html>
<html lang="it">
<head>
    <title>MusicWave - Admin Dashboard</title>
    <meta charset="UTF-8">
    <style>
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f4f4f4; }
        .btn-premium { background-color: #4CAF50; color: white; padding: 6px 12px; border: none; cursor: pointer; }
        .btn-normal { background-color: #f44336; color: white; padding: 6px 12px; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <h1>Administration Panel - MusicWave</h1>
    <p>Welcome, Administrator (ID: <?php echo htmlspecialchars($_SESSION['user_id']); ?>)</p>
    <p><a href="dashboard.php">Return to the Main Dashboard</a> | <a href="logout.php">Logout</a></p>

    <?php if ($message): ?>
        <p style="color: green; font-weight: bold;"><?php echo htmlspecialchars($message); ?></p>
    <?php endif; ?>
    <?php if ($error_message): ?>
        <p style="color: red; font-weight: bold;"><?php echo htmlspecialchars($error_message); ?></p>
    <?php endif; ?>

    <h2>User Privilege Management</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Account Status</th>
                <th>Current Privilege</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php if (empty($users_list)): ?>
                <tr>
                    <td colspan="6">No users registered in the system other than administrators.</td>
                </tr>
            <?php else: ?>
                <?php foreach ($users_list as $u): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($u['id']); ?></td>
                        <td><?php echo htmlspecialchars($u['username']); ?></td>
                        <td><?php echo htmlspecialchars($u['email']); ?></td>
                        <td><?php echo htmlspecialchars($u['status']); ?></td>
                        <td><strong><?php echo strtoupper(htmlspecialchars($u['role'])); ?></strong></td>
                        <td>
                            <form method="POST" action="admin_dashboard.php" style="display:inline;">
                                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                <input type="hidden" name="target_user_id" value="<?php echo htmlspecialchars($u['id']); ?>">
                                
                                <?php if ($u['role'] === 'premium'): ?>
                                    <input type="hidden" name="action" value="make_non_premium">
                                    <button type="submit" class="btn-normal">Revoke Premium (Make Standard)</button>
                                <?php else: ?>
                                    <input type="hidden" name="action" value="make_premium">
                                    <button type="submit" class="btn-premium">Make Premium</button>
                                <?php endif; ?>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>
</body>
</html>
