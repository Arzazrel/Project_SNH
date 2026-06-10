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
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f6f9; margin: 0; padding: 20px; }
        .header-hud { display: flex; justify-content: space-between; align-items: center; background-color: #2b7a78; color: white; padding: 15px 30px; border-radius: 8px; margin-bottom: 20px; }
        .header-hud h1 { margin: 0; font-size: 24px; }
        .welcome-text { font-size: 16px; font-weight: bold; }
        .badge-premium { background-color: #f1c40f; color: #17252a; padding: 3px 8px; border-radius: 4px; font-size: 12px; margin-left: 5px; }
        .badge-standard { background-color: #bdc3c7; color: #17252a; padding: 3px 8px; border-radius: 4px; font-size: 12px; margin-left: 5px; }
        .nav-buttons { display: flex; gap: 15px; margin-bottom: 20px; align-items: center; }
        .btn { padding: 10px 20px; font-size: 15px; border: none; border-radius: 5px; cursor: pointer; text-decoration: none; font-weight: bold; transition: background 0.2s; }
        .btn-menu { background-color: #3aafa9; color: white; }
        .btn-menu:hover, .btn-menu.active { background-color: #17252a; }
        .btn-upload { background-color: #f39c12; color: white; }
        .btn-upload:hover { background-color: #d35400; }
        .btn-logout { background-color: #e74c3c; color: white; }
        .btn-logout:hover { background-color: #c0392b; }
        .search-form { display: flex; gap: 10px; margin-left: auto; }
        .search-input { padding: 8px 12px; width: 250px; border: 1px solid #ccc; border-radius: 5px; }
        .main-content-rect { background-color: white; border: 2px solid #def2f1; border-radius: 8px; min-height: 400px; padding: 25px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
        .empty-state { color: #7f8c8d; text-align: center; margin-top: 150px; font-style: italic; }
        .badge-file-premium { background: #f1c40f; color: #000; padding: 2px 5px; font-size: 10px; font-weight: bold; border-radius: 3px; }
    </style>
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
