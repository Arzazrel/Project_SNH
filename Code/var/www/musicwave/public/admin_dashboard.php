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
if (!isset($_SESSION['user_id']) || !isset($_SESSION['role']) || $_SESSION['role'] !== 'admin') {
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

$success_message = "";
$error_message = "";

// management of State Change (Promotion / Degradation) via POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // check presence and validity of the token. Use of hash_equals to prevent timing attack during string comparision (apply Costant-Time Comparison)
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        global $securityLogger;
    	$securityLogger->warning("Admin CSRF attempt blocked on privilege modification", ["admin_id" => $_SESSION['user_id'], "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);		// write in security log
    	header("HTTP/1.1 403 Forbidden");			// redirect ot an error page to visualize the attack for the user
    	exit("Security Error: Invalid or missing CSRF Token.");
    }
    unset($_SESSION['csrf_token']);		// one-time use-> destroy the token immediately after verification to prevent reuse

    // Recovery and sanitization of operation inputs
    $target_user_id = isset($_POST['target_user_id']) ? (int)$_POST['target_user_id'] : 0;	// get user_id
    $action = $_POST['action'] ?? '';								// get type of operation

    // control check for target user_id and opertion type
    if ($target_user_id === (int)$_SESSION['user_id']) {
        $error_message = "Operation Denied: You cannot modify your own administrative role.";
    }elseif ($target_user_id <= 0 || !in_array($action, ['make_premium', 'make_non_premium'])) {
        $error_message = "Invalid action parameters.";							// error
    } elseif ($target_user_id > 0 && in_array($action, ['make_premium', 'make_non_premium'], true)) {
        // 
        $new_role = ($action === 'make_premium') ? 'premium' : 'standard';

	try {
            // perform the update on the DB with a Prepared Statement. Role values ('standard', 'premium', 'admin')
            $stmt = $conn->prepare("UPDATE users SET role = ? WHERE id = ? AND role != 'admin'");
            $stmt->bind_param("si", $new_role, $target_user_id);
            $stmt->execute();
            
            // update check
            if ($stmt->affected_rows > 0) {							// update success
                $success_message = "User privilege updated successfully.";        
                // Detailed action logging. An action that modifies privileges must be tracked at all times, not only for post-incident investigation purposes.
                $accessLogger->info("Administrator changed user privilege status", ["admin_id" => $_SESSION['user_id'] ,"target_user_id" => $target_user_id, "new_privilege" => $new_role, "ip" => $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP']);
            } else {
                $error_message = "Failed to update privileges. User might not exist or is an admin.";		// update failed
            }
            
            $stmt->close();
        } catch (Throwable $e) {
            $securityLogger->error("Database error during role modification", ["error" => $e->getMessage()]);
            $error_message = "An internal database error occurred while committing state changes.";
        }
    }
    // regenerate a new anti-CSRF token for the form in case the page is reloaded with errors.
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// retrieve the list of users to display in the table (Prepared Statement without external dynamic parameters)
// select only users with editable roles (we exclude other administrators for security reasons)
// Secure Pagination Control Setup
$current_page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
if ($current_page < 1) {
    $current_page = 1;
}

$records_per_page = 10;
$offset = ($current_page - 1) * $records_per_page;

try {
    // Count total manageable non-admin records
    $count_query = "SELECT COUNT(*) FROM users WHERE role != 'admin'";
    $count_stmt = $conn->prepare($count_query);
    $count_stmt->execute();
    $total_records = $count_stmt->get_result()->fetch_row()[0];
    $count_stmt->close();
    
    $total_pages = ceil($total_records / $records_per_page) ?: 1;
    if ($current_page > $total_pages) {
        $current_page = $total_pages;
        $offset = ($current_page - 1) * $records_per_page;
    }
    
    // Fetch user subset with secure bound parameterized layout limits
    $fetch_query = "SELECT id, username, email, role, created_at FROM users WHERE role != 'admin' ORDER BY username ASC LIMIT ? OFFSET ?";
    $fetch_stmt = $conn->prepare($fetch_query);
    $fetch_stmt->bind_param("ii", $records_per_page, $offset);
    $fetch_stmt->execute();
    $users_list = $fetch_stmt->get_result();
} catch (Throwable $e) {
    $securityLogger->error("Database error loading user list in admin dashboard", ["error" => $e->getMessage()]);
    die("An error occurred while loading dashboard contents. Please try again later.");
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MusicWave - Admin Dashboard</title>
    <link rel="stylesheet" href="css/style.css"> 
</head>
<body>

    <header class="header-hud">
        <h1>MusicWave Management Node</h1>
        <div class="welcome-text">
            Admin Workspace Session | User ID: <?php echo htmlspecialchars($_SESSION['user_id'], ENT_QUOTES, 'UTF-8'); ?>
        </div>
    </header>

    <nav class="nav-buttons">
        <!--
        The project specifications don't require admins to be able to use the shared user dashboard, so removing the button will limit its functionality. Simply remove the comments if you want to implement it. 
        <a href="dashboard.php" class="btn btn-menu">Main Dashboard</a> 
        -->
        <a href="logout.php" class="btn btn-logout">Logout System</a>
    </nav>

    <main class="main-content-rect">
        <div class="repo-header">
            <h3 class="section-title">User Account Privilege Registry</h3>
            <p class="text-muted">Review, promote, or revoke Premium tier privileges for registered application workspace accounts.</p>
        </div>

        <?php if (!empty($success_message)): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success_message, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        
        <?php if (!empty($error_message)): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error_message, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>

        <table class="lyrics-table">
            <thead>
		<tr>
		    <th class="col-username">Username</th>
		    <th class="col-email">Email Address</th>
		    <th class="col-tier">Current Tier</th>
		    <th class="col-date">Registered At</th>
		    <th class="col-actions">Actions</th>
		</tr>
	    </thead>
            <tbody>
                <?php if ($total_records === 0): ?>
                    <tr>
                        <td colspan="5" class="empty-table-msg">No manageable standard or premium users cataloged in the infrastructure registry database.</td>
                    </tr>
                <?php else: ?>
                    <?php 
                    $count = 0;
                    while ($user = $users_list->fetch_assoc()): 
                        $count++;
                        $is_last = ($count === $users_list->num_rows);
                        $row_class = $is_last ? 'last-row' : '';
                    ?>
                        <tr class="<?php echo $row_class; ?>">
                            <td><div class="lyrics-table-title"><?php echo htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8'); ?></div></td>
                            <td><div class="lyrics-table-author"><?php echo htmlspecialchars($user['email'], ENT_QUOTES, 'UTF-8'); ?></div></td>
                            <td>
                                <?php if ($user['role'] === 'premium'): ?>
                                    <span class="badge-file-premium">PREMIUM</span>
                                <?php else: ?>
                                    <span class="badge-file-standard">STANDARD</span>
                                <?php endif; ?>
                            </td>
                            <td><span class="lyrics-table-date"><?php echo htmlspecialchars($user['created_at'], ENT_QUOTES, 'UTF-8'); ?></span></td>
                            <td class="text-center">
                                <form method="POST" action="admin_dashboard.php" style="margin: 0;">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                                    <input type="hidden" name="target_user_id" value="<?php echo htmlspecialchars($user['id'], ENT_QUOTES, 'UTF-8'); ?>">
                                    
                                    <?php if ($user['role'] === 'premium'): ?>
                                        <input type="hidden" name="action" value="make_non_premium">
                                        <button type="submit" class="action-button btn-demote">Revoke</button>
                                    <?php else: ?>
                                        <input type="hidden" name="action" value="make_premium">
                                        <button type="submit" class="action-button btn-promote">Promote</button>
                                    <?php endif; ?>
                                </form>
                            </td>
                        </tr>
                    <?php endwhile; ?>
                <?php endif; ?>
            </tbody>
        </table>

        <div class="pagination-container">
            <?php if ($total_pages > 1): ?>
                <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                    <a href="admin_dashboard.php?page=<?php echo $i; ?>" class="page-link <?php echo ($i === $current_page) ? 'active' : ''; ?>">
                        <?php echo $i; ?>
                    </a>
                <?php endfor; ?>
            <?php endif; ?>
        </div>
    </main>

    <?php $fetch_stmt->close(); ?>
</body>
</html>
