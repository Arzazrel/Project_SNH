<?php
/**
 * INDEX PAGE / LANDING PAGE
 * Acts as the default application entry point and prevents Directory Listing.
 */

// HTTP Header Hardening (Active Security)
require_once __DIR__ . '/../config/db_config.php';
require_once DIR_INCLUDES . 'security_utils.php';
SecurityUtils::sendSecurityHeaders();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MusicWave - Welcome</title>
    
    <link rel="stylesheet" href="css/style.css">
</head>
<body>

    <div class="auth-wrapper">
        <div class="auth-container">
            
            <div class="auth-header">
                <h2>MusicWave</h2>
                <p>Secure Lyrics & Music Platform</p>
            </div>
            
            <div class="margin-top-md">
                <a href="login.php" class="btn btn-menu">Login</a>
                <a href="register.php" class="btn btn-menu">Register</a>
            </div>
            
            <div class="footer-links text-muted">
                &copy; <?php echo date("Y"); ?> MusicWave. All rights reserved.
            </div>
            
        </div>
    </div>

</body>
</html>
