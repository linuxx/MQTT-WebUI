<?php
/**
 * Logout page
 */

require_once __DIR__ . '/../includes/bootstrap.php';

$auth->logout();
header('Location: ' . APP_URL . '/public/login.php?logout=1');
exit;
