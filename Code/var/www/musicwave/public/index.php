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
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f7f6;
            color: #333;
            text-align: center;
            padding: 50px;
        }
        .container {
            max-width: 500px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2b7a78;
            margin-bottom: 10px;
        }
        p {
            color: #666;
            margin-bottom: 30px;
        }
        .btn {
            display: inline-block;
            background-color: #2b7a78;
            color: white;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
            margin: 0 10px;
            transition: background 0.2s;
        }
        .btn:hover {
            background-color: #1a5251;
        }
        .footer {
            margin-top: 40px;
            font-size: 0.8em;
            color: #aaa;
        }
    </style>
</head>
<body>

    <div class="container">
        <h1>MusicWave</h1>
        <p>Secure Lyrics & Music Platform</p>
        
        <a href="login.php" class="btn">Login</a>
        <a href="register.php" class="btn">Register</a>
        
        <div class="footer">
            &copy; <?php echo date("Y"); ?> MusicWave. All rights reserved.
        </div>
    </div>

</body>
</html>
