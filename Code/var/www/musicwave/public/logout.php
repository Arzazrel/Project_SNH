<?php
/**
 * LOGOUT CONTROLLER
 * Safely handles application logout via centralized SecurityUtils.
 */

require_once __DIR__ . '/../config/db_config.php';
require_once DIR_INCLUDES . 'security_utils.php';

SecurityUtils::startSecureSession();
SecurityUtils::destroySession();		// destroy the session files and client cookies

header("Location: login.php?msg=logged_out");	// send back to login screen with explicit feedback
exit();
