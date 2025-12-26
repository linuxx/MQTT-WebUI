<?php
/**
 * Deprecated: API key creation now handled in dashboard
 */

require_once __DIR__ . '/../../includes/bootstrap.php';

$auth->requireLogin();
header('Location: ' . APP_URL . '/public/user/dashboard.php');
exit;
