<?php
/**
 * MAIN DASHBOARD CONTROLLER & VIEW
 * It manages secure access, security logs, XSS checks, and the skeleton of the modular architecture interface.
 */

// Load configuration and dependencies
require_once __DIR__ . '/../config/db_config.php';
require_once DIR_INCLUDES . 'db_connect.php';
require_once DIR_INCLUDES . 'logger_setup.php';
require_once DIR_INCLUDES . 'security_utils.php';

SecurityUtils::startSecureSession();	// start secure session

// Access control: If the user is not authenticated, we log the event and redirect to the login page.
if (!isset($_SESSION['user_id'])) {
    global $securityLogger;
    
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN_IP';		// take user ip for the log
    $requested_uri = $_SERVER['REQUEST_URI'] ?? 'dashboard.php';	// take the requested uri for the log
    
    $securityLogger->warning("Unauthorized dashboard access attempt intercepted", ["client_ip" => $client_ip,"requested_url" => $requested_uri]);
    
    header("Location: login.php?error=unauthorized");			// redirect
    exit();
}

SecurityUtils::sendSecurityHeaders();	// security headers

// User Role Management (Standard / Premium)
$user_role = $_SESSION['role'] ?? 'standard'; 	// Login expected value: 'standard' or 'premium'
$is_user_premium = ($user_role === 'premium');

// -- layout management --
// Current View Management (lyrics, audio, or blank at the beginning). Determines which panel to display within the central rectangle.
// This variable is used to decide which submodule should be injected into the central rectangle of the page (by the HTML switch at the bottom of the page).
$current_view = SecurityUtils::sanitizeInput($_GET['view'] ?? '');	// get 
if (!in_array($current_view, ['lyrics', 'audio', 'search'])) {
    $current_view = ''; 						// start view (empty rectangle)
}

// Prepares the search variable if sent via GET.
$search_query = SecurityUtils::sanitizeInput($_GET['query'] ?? '');
if (!empty($search_query) && in_array($current_view, ['lyrics', 'audio'])) {
    $current_view = 'search'; 							// If there is an active search (word searched by the user), we force the search form
}

$safe_username = htmlspecialchars($_SESSION['username'] ?? 'Utente', ENT_QUOTES, 'UTF-8');	// get current username to print in the layout (with XSS prevention)
$safe_role = htmlspecialchars(strtoupper($user_role), ENT_QUOTES, 'UTF-8');
?>

<!DOCTYPE html>
<html lang="it">
<head>
    <title>MusicWave - Dashboard</title>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="<?php echo WEB_CSS; ?>style.css">
</head>
<body>

    <header class="header-hud">
        <h1>MusicWave</h1>
        <div class="welcome-text">
            Welcome, <?php echo $safe_username; ?>!
            <span class="<?php echo $is_user_premium ? 'badge-premium' : 'badge-standard'; ?>">
                <?php echo $safe_role; ?>
            </span>
        </div>
        <a href="logout.php" class="btn btn-logout">LOGOUT</a>
    </header>

    <nav class="nav-buttons">
        <a href="dashboard.php?view=lyrics" class="btn btn-menu <?php echo $current_view === 'lyrics' ? 'active' : ''; ?>">LYRICS</a>
        <a href="dashboard.php?view=audio" class="btn btn-menu <?php echo $current_view === 'audio' ? 'active' : ''; ?>">AUDIO</a>
        
        <a href="upload.php" class="btn btn-upload">UPLOAD MEDIA</a>
        
        <form method="GET" action="dashboard.php" class="search-form">
            <input type="hidden" name="view" value="<?php echo htmlspecialchars($current_view === 'search' ? ($_GET['context'] ?? 'lyrics') : $current_view); ?>">
            
            <input type="text" name="query" class="search-input" 
                   placeholder="Search among <?php echo ($current_view === 'audio' || (isset($_GET['context']) && $_GET['context'] === 'audio')) ? 'audios...' : 'lyrics...'; ?>"
                   value="<?php echo htmlspecialchars($search_query, ENT_QUOTES, 'UTF-8'); ?>"
                   <?php echo empty($current_view) || ($current_view === 'search' && empty($_GET['context'])) ? 'disabled placeholder="Select a section first"' : ''; ?>>
            
            <button type="submit" class="btn btn-menu" <?php echo empty($current_view) || ($current_view === 'search' && empty($_GET['context'])) ? 'disabled' : ''; ?>>SEARCH</button>
        </form>
    </nav>

    <main class="main-content-rect">
        <?php
        switch ($current_view) {
            case 'lyrics':
                include DIR_PUBLIC . 'lyrics_panel.php'; 
                break;
                
            case 'audio':
                include DIR_PUBLIC . 'audio_panel.php'; 
                break;
                
            case 'search':
                echo "<h3>Searcj results</h3><p>Search panel loaded! You searched for: <strong>" . htmlspecialchars($search_query, ENT_QUOTES, 'UTF-8') . "</strong></p>";
                include DIR_PUBLIC . 'search_results.php';
                break;
                
            default:
                // initial state or empty rectangle
                echo '<div class="empty-state">Select a section (Lyrics or Audio) from the top menu to get started.</div>';
                break;
        }
        ?>
    </main>

</body>
</html>
