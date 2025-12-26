<?php
/**
 * Front controller — load app and route to appropriate page
 */

// Bootstrap the application
require_once __DIR__ . '/includes/bootstrap.php';

// If auth initialized, route accordingly
if (isset($auth) && $auth->isAuthenticated()) {
    header('Location: ' . APP_URL . '/public/user/dashboard.php');
    exit;
}

// Not authenticated — redirect to public login
header('Location: ' . APP_URL . '/public/login.php');
exit;

?>
