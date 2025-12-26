<?php
/**
 * MQTT Web UI Configuration (sample)
 *
 * Copy this file to config.php and edit the values for your environment.
 * Keep config.php out of the web root and out of git.
 */

// Database Configuration
define('DB_HOST', 'localhost'); // MySQL host
define('DB_PORT', 3306); // MySQL port
define('DB_NAME', 'dbMQTT'); // Database name (matches sql/schema.sql)
define('DB_USER', 'username'); // Database username
define('DB_PASS', 'password'); // Database password

// MQTT Broker Configuration (used by the HTTP publish endpoint)
define('MQTT_HOST', 'localhost'); // Broker host or IP
define('MQTT_PORT', 1883); // Broker cleartext port
// Use the same credentials you create for the global admin user (api_user).
define('MQTT_USER', 'api_user'); // MQTT username used by the API publisher
define('MQTT_PASS', 'password'); // MQTT password used by the API publisher

// MQTT port settings (displayed to users on the dashboard)
define('MQTT_CLEAR_PORT_OPEN', true); // Whether the cleartext port is reachable
define('MQTT_CLEAR_PORT_NUMBER', 1883); // Cleartext port number
define('MQTT_TLS_PORT_OPEN', true); // Whether TLS port is reachable
define('MQTT_TLS_PORT_NUMBER', 8883); // TLS port number

// Session Security Configuration
define('SESSION_SECURE', true); // Send cookies only over HTTPS
define('SESSION_HTTPONLY', true); // Prevent JS access to session cookies
define('SESSION_SAMESITE', 'Lax'); // CSRF protection policy
define('SESSION_TIMEOUT', 3600); // Idle timeout in seconds

// Application Configuration
define('APP_NAME', 'MQTT Admin'); // UI display name
define('APP_URL', 'https://mqtt.website.com'); // Base application URL (use HTTPS)
define('APP_TIMEZONE', 'America/New_York'); // PHP default timezone
define('APP_ENV', 'production'); // 'production' or 'development'

// Password Policy
define('PASSWORD_MIN_LENGTH', 8); // Minimum password length
define('PASSWORD_REQUIRE_UPPERCASE', true); // Require uppercase letters
define('PASSWORD_REQUIRE_LOWERCASE', true); // Require lowercase letters
define('PASSWORD_REQUIRE_NUMBERS', true); // Require numbers
define('PASSWORD_REQUIRE_SYMBOLS', false); // Require symbols

// API Configuration
define('API_KEY_LENGTH', 32); // Length of random API keys
// API audit logging (can grow quickly in high-traffic environments)
define('API_AUDIT_LOG_ENABLED', true); // Enable/disable API publish audit logs
//define('API_RATE_LIMIT', 100); // Requests per minute (not implemented)
//define('API_RATE_WINDOW', 60); // Seconds (not implemented)

// Logging
//define('LOG_DIR', __DIR__ . '/../logs'); // Log directory (not implemented)
//define('LOG_LEVEL', 'info'); // 'debug', 'info', 'warning', 'error' (not implemented)

// Security Headers
define('SECURITY_HEADERS_ENABLED', true); // Enable browser security headers
define('CSRF_TOKEN_LENGTH', 32); // CSRF token length
define('CSRF_TOKEN_TIMEOUT', 3600); // CSRF token lifetime in seconds

// Password Hashing (PBKDF2, mosquitto-auth-plug compatible)
// Format: PBKDF2$<algo>$<iterations>$<salt_b64>$<hash_b64>
define('PBKDF2_ITERATIONS', 901); // PBKDF2 iteration count
define('PBKDF2_SALT_BYTES', 12); // Salt byte length
define('PBKDF2_HASH_ALGO', 'sha256'); // Hash algorithm
define('PBKDF2_DERIVED_KEY_BYTES', 24); // Derived key length

// Set timezone for PHP date/time functions
date_default_timezone_set(APP_TIMEZONE);

// Error reporting (adjust for production)
if (APP_ENV === 'development') {
    error_reporting(E_ALL); // Log all errors
    ini_set('display_errors', '0'); // Log, do not display
    ini_set('log_errors', '1'); // Enable PHP error log
} else {
    error_reporting(E_ALL); // Keep logging enabled in production
    ini_set('display_errors', '0'); // Never display errors to users
    ini_set('log_errors', '1'); // Enable PHP error log
}

// Set session parameters
ini_set('session.gc_maxlifetime', SESSION_TIMEOUT); // Session garbage collection lifetime
ini_set('session.cookie_httponly', SESSION_HTTPONLY ? 1 : 0); // HttpOnly cookies
ini_set('session.cookie_secure', SESSION_SECURE ? 1 : 0); // Secure cookies
ini_set('session.cookie_samesite', SESSION_SAMESITE); // SameSite policy

// Prevent caching of sensitive pages
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0'); // Disable caching
header('Pragma: no-cache'); // HTTP/1.0 cache control
header('Expires: 0'); // Expire immediately

// Security headers
if (SECURITY_HEADERS_ENABLED) {
    header('X-Content-Type-Options: nosniff'); // Prevent MIME sniffing
    header('X-Frame-Options: DENY'); // Prevent clickjacking
    header('X-XSS-Protection: 1; mode=block'); // Basic XSS protection
    header('Referrer-Policy: strict-origin-when-cross-origin'); // Limit referrer data
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()'); // Disable sensors
}
