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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MusicWave - Admin Dashboard</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #eef2f3;
            margin: 0;
            padding: 0;
            color: #334155;
        }
        .navbar {
            background-color: #2b7a78;
            color: white;
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .navbar h1 { margin: 0; font-size: 22px; font-weight: bold; letter-spacing: 0.5px; }
        .user-badge {
            background-color: #17252a;
            padding: 4px 10px;
            font-size: 11px;
            font-weight: bold;
            border-radius: 4px;
            text-transform: uppercase;
            margin-left: 5px;
            vertical-align: middle;
            color: #feffff;
        }
        .btn-logout {
            background-color: #e11d48;
            color: white;
            padding: 8px 16px;
            text-decoration: none;
            border-radius: 4px;
            font-weight: 600;
            font-size: 13px;
            transition: background 0.2s;
        }
        .btn-logout:hover { background-color: #be123c; }
        .main-container { max-width: 1400px; margin: 30px auto; padding: 0 20px; }
        .action-bar { margin-bottom: 20px; display: flex; gap: 10px; }
        .btn-nav {
            background-color: #3aafa9;
            color: white;
            padding: 10px 18px;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
            font-size: 13px;
            text-transform: uppercase;
        }
        .btn-nav:hover { background-color: #2b7a78; }
        .dashboard-box {
            background: white;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            border: 1px solid #e2e8f0;
        }
        .info-header { margin-bottom: 25px; border-bottom: 1px solid #e2e8f0; padding-bottom: 15px; }
        .info-header h2 { margin: 0 0 6px 0; color: #17252a; font-size: 20px; }
        .info-header span { color: #64748b; font-size: 14px; }
        
        /* Tabella stilizzata */
        .admin-table { width: 100%; border-collapse: separate; border-spacing: 0; table-layout: fixed; border: 1px solid #cbd5e1; border-radius: 6px; overflow: hidden; }
        .admin-table th { background-color: #f8fafc; padding: 12px 15px; border-bottom: 2px solid #cbd5e1; color: #334155; font-weight: 600; text-align: left; }
        .admin-table td { padding: 12px 15px; color: #0f172a; font-size: 14px; vertical-align: middle; }
        
        /* Badges Privilegi */
        .badge-premium { background: #3aafa9; color: white; padding: 3px 8px; font-size: 11px; font-weight: bold; border-radius: 4px; }
        .badge-standard { background: #e2e8f0; color: #334155; padding: 3px 8px; font-size: 11px; font-weight: bold; border-radius: 4px; }
        .badge-status { background: #f1f5f9; color: #475569; padding: 3px 8px; font-size: 11px; font-weight: 500; border-radius: 12px; border: 1px solid #cbd5e1; text-transform: capitalize; }
        
        /* Bottoni Azione Form */
        .action-button { padding: 6px 14px; border: none; border-radius: 4px; color: white; font-weight: 600; font-size: 12px; cursor: pointer; transition: background 0.15s; }
        .btn-promote { background-color: #10b981; }
        .btn-promote:hover { background-color: #059669; }
        .btn-demote { background-color: #ef4444; }
        .btn-demote:hover { background-color: #dc2626; }
        
        .alert { padding: 12px 15px; border-radius: 6px; margin-bottom: 20px; font-weight: 500; font-size: 14px; }
        .alert-success { background: #d1fae5; border: 1px solid #a7f3d0; color: #065f46; }
        .alert-danger { background: #fee2e2; border: 1px solid #fca5a5; color: #991b1b; }
    </style>
</head>
<body>

    <div class="navbar">
        <div>
            <h1>MusicWave <span class="user-badge" style="background:#17252a;">Administrator</span></h1>
        </div>
        <div style="font-size: 14px; font-weight: 500;">
            Welcome, Administrator (ID: <?php echo htmlspecialchars($_SESSION['user_id'], ENT_QUOTES, 'UTF-8'); ?>)
            <a href="logout.php" class="btn-logout" style="margin-left: 20px;">LOGOUT</a>
        </div>
    </div>

    <div class="main-container">
        <!--
        The app's use cases do not specify that admin can see content like normal users, so this feature will be kept for future implementations.
        <div class="action-bar">
            <a href="dashboard.php" class="btn-nav">« Return to Main Dashboard</a>
        </div>
        -->

        <div class="dashboard-box">
            
            <div class="info-header">
                <h2>User Privilege Management</h2>
                <span>Promote or demote user account operational scopes inside the database architecture.</span>
            </div>

            <?php if ($message): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></div>
            <?php endif; ?>
            <?php if ($error_message): ?>
                <div class="alert alert-danger"><?php echo htmlspecialchars($error_message, ENT_QUOTES, 'UTF-8'); ?></div>
            <?php endif; ?>

            <table class="admin-table">
                <thead>
                    <tr>
                        <th style="width: 8%;">ID</th>
                        <th style="width: 22%;">Username</th>
                        <th style="width: 25%;">Email</th>
                        <th style="width: 15%;">Account Status</th>
                        <th style="width: 15%;">Current Privilege</th>
                        <th style="width: 15%; text-align: center;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($users_list)): ?>
                        <tr>
                            <td colspan="6" style="text-align: center; padding: 30px; color: #64748b;">No users registered in the system other than administrators.</td>
                        </tr>
                    <?php else: ?>
                        <?php 
                        $cnt = 0;
                        foreach ($users_list as $u): 
                            $cnt++;
                            $bg_color = ($cnt % 2 === 0) ? '#f8fafc' : '#ffffff';
                            $border_bottom = ($cnt === count($users_list)) ? 'none' : '1px solid #e2e8f0';
                        ?>
                            <tr style="background-color: <?php echo $bg_color; ?>;">
                                <td style="border-bottom: <?php echo $border_bottom; ?>; font-weight: 600; color: #64748b;"><?php echo htmlspecialchars($u['id'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td style="border-bottom: <?php echo $border_bottom; ?>; font-weight: 500;"><?php echo htmlspecialchars($u['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td style="border-bottom: <?php echo $border_bottom; ?>; color: #475569;"><?php echo htmlspecialchars($u['email'], ENT_QUOTES, 'UTF-8'); ?></td>
                                <td style="border-bottom: <?php echo $border_bottom; ?>;">
                                    <span class="badge-status"><?php echo htmlspecialchars($u['status'], ENT_QUOTES, 'UTF-8'); ?></span>
                                </td>
                                <td style="border-bottom: <?php echo $border_bottom; ?>;">
                                    <?php if ($u['role'] === 'premium'): ?>
                                        <span class="badge-premium">PREMIUM</span>
                                    <?php else: ?>
                                        <span class="badge-standard">STANDARD</span>
                                    <?php endif; ?>
                                </td>
                                <td style="border-bottom: <?php echo $border_bottom; ?>; text-align: center;">
                                    <form method="POST" action="admin_dashboard.php" style="margin:0;">
                                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                                        <input type="hidden" name="target_user_id" value="<?php echo htmlspecialchars($u['id'], ENT_QUOTES, 'UTF-8'); ?>">
                                        
                                        <?php if ($u['role'] === 'premium'): ?>
                                            <input type="hidden" name="action" value="make_non_premium">
                                            <button type="submit" class="action-button btn-demote">Revoke Premium</button>
                                        <?php else: ?>
                                            <input type="hidden" name="action" value="make_premium">
                                            <button type="submit" class="action-button btn-promote">Make Premium</button>
                                        <?php endif; ?>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>

        </div>
    </div>

</body>
</html>
