<?php
/**
 * Bootstrap - Initialize application
 * Include this at the start of every PHP page
 */

// Define application base path
if (!defined('APP_BASE')) {
    define('APP_BASE', dirname(__FILE__) . '/..');
}

// Load configuration
require_once APP_BASE . '/config/config.php';

// Autoload classes
spl_autoload_register(function ($class) {
    $paths = [
        APP_BASE . '/src/' . $class . '.php',
        APP_BASE . '/includes/' . $class . '.php',
    ];

    foreach ($paths as $path) {
        if (file_exists($path)) {
            require_once $path;
            return;
        }
    }
});

// Initialize authentication
$auth = new AuthManager();
$auth->initSession();

// Handle global change password action
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['change_password'])) {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception('CSRF validation failed');
        }

        if (!$auth->isAuthenticated()) {
            throw new Exception('You must be logged in');
        }

        $currentPassword = $_POST['current_password'] ?? '';
        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';

        if ($newPassword !== $confirmPassword) {
            throw new Exception('New password and confirmation do not match');
        }

        $userManager = new UserManager();
        $userManager->changePassword($auth->getUserId(), $currentPassword, $newPassword);

        $_SESSION['flash_success'] = 'Password updated successfully';
    } catch (Exception $e) {
        $_SESSION['flash_error'] = $e->getMessage();
    }

    header('Location: ' . $_SERVER['REQUEST_URI']);
    exit;
}

// Set response headers for security
if (!headers_sent()) {
    // CORS (adjust for production)
    header('Access-Control-Allow-Origin: ' . APP_URL);
    
    // Content security
    header('Content-Type: text/html; charset=utf-8');
    
    // X-Frame-Options already set in config.php
}

// Global error handler
set_error_handler(function ($errno, $errstr, $errfile, $errline) {
    error_log("[PHP ERROR] $errstr in $errfile on line $errline");
    if (APP_ENV === 'production') {
        // Don't expose details to user
        http_response_code(500);
        die('An error occurred. Please contact administrator.');
    }
});

// Global exception handler
set_exception_handler(function ($exception) {
    error_log("[PHP EXCEPTION] " . $exception->getMessage());
    if (APP_ENV === 'production') {
        http_response_code(500);
        die('An error occurred. Please contact administrator.');
    } else {
        die('<pre>' . htmlspecialchars($exception) . '</pre>');
    }
});
