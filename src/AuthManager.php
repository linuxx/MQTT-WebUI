<?php
/**
 * Authentication manager
 * Handles login, logout, session management, and user authentication
 */

class AuthManager {
    
    private $db;
    private $auditLogger;
    
    const MAX_LOGIN_ATTEMPTS = 5;
    const LOGIN_ATTEMPT_WINDOW = 900; // 15 minutes
    
    public function __construct() {
        $this->db = Database::getInstance();
        $this->auditLogger = new AuditLogger();
    }
    
    /**
     * Initialize secure session
     */
    public function initSession() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        // Regenerate session ID for security
        if (empty($_SESSION['session_initialized'])) {
            session_regenerate_id(true);
            $_SESSION['session_initialized'] = true;
            $_SESSION['created_at'] = time();
        }
        
        // Check session timeout
        if (isset($_SESSION['last_activity']) && 
            (time() - $_SESSION['last_activity']) > SESSION_TIMEOUT) {
            $this->logout();
            return false;
        }
        
        $_SESSION['last_activity'] = time();
        return true;
    }
    
    /**
     * Authenticate user with username and password
     * @param string $username
     * @param string $password
     * @return bool
     */
    public function login($username, $password) {
        // Sanitize input
        $username = SecurityUtil::sanitize($username);
        $password = SecurityUtil::sanitize($password);
        
        // Check for brute force attempts
        if ($this->isLockedOut($username)) {
            $this->auditLogger->logFailedLogin($username);
            throw new Exception("Too many failed login attempts. Please try again later.");
        }
        
        try {
            // Fetch user from database
            $user = $this->db->fetchOne(
                'SELECT id, username, password, super AS is_super, is_enabled FROM tbUsers WHERE username = ? AND is_enabled = 1',
                [$username]
            );
            
            // User not found or disabled - still hash to prevent timing attacks
            if (!$user) {
                SecurityUtil::verifyPassword($password, '$2y$10$invalidhash');
                $this->recordFailedLogin($username);
                $this->auditLogger->logFailedLogin($username);
                throw new Exception("Invalid username or password");
            }
            
            // Verify password with timing-safe comparison
            if (!SecurityUtil::verifyPassword($password, $user['password'])) {
                $this->recordFailedLogin($username);
                $this->auditLogger->logFailedLogin($username);
                throw new Exception("Invalid username or password");
            }
            
            // Check if password needs rehashing
            if (SecurityUtil::passwordNeedsRehash($user['password'])) {
                $newHash = SecurityUtil::hashPassword($password);
                $this->db->update('tbUsers', ['password' => $newHash], 'id = ?', [$user['id']]);
            }
            
            // Clear failed login attempts
            $this->clearFailedLogins($username);
            
            // Create session
            $this->initSession();
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['is_super'] = (bool)$user['is_super'];
            
            // Create CSRF token
            SecurityUtil::createCsrfToken();
            
            // Log successful login
            $this->auditLogger->logLogin($user['id'], $username);
            
            return true;
            
        } catch (Exception $e) {
            throw $e;
        }
    }
    
    /**
     * Check if user is logged in
     */
    public function isAuthenticated() {
        $this->initSession();
        return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
    }
    
    /**
     * Check if user is superuser
     */
    public function isSuper() {
        $this->initSession();
        return isset($_SESSION['is_super']) && $_SESSION['is_super'] === true;
    }
    
    /**
     * Get current user ID
     */
    public function getUserId() {
        $this->initSession();
        return $_SESSION['user_id'] ?? null;
    }
    
    /**
     * Get current username
     */
    public function getUsername() {
        $this->initSession();
        return $_SESSION['username'] ?? null;
    }
    
    /**
     * Logout current user
     */
    public function logout() {
        if (isset($_SESSION['user_id'])) {
            $userId = $_SESSION['user_id'];
            $username = $_SESSION['username'] ?? 'Unknown';
            
            // Log logout
            $this->auditLogger->logLogout($userId, $username);
        }
        
        // Clear session
        $_SESSION = [];
        
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(
                session_name(),
                '',
                time() - 42000,
                $params["path"],
                $params["domain"],
                $params["secure"],
                $params["httponly"]
            );
        }
        
        session_destroy();
    }
    
    /**
     * Check if user account is locked out due to failed attempts
     */
    private function isLockedOut($username) {
        $lockoutKey = 'login_attempts_' . md5($username);
        
        if (isset($_SESSION[$lockoutKey])) {
            $attempts = $_SESSION[$lockoutKey];
            if ($attempts['count'] >= self::MAX_LOGIN_ATTEMPTS) {
                // Check if lockout window has expired
                if (time() - $attempts['first_attempt'] < self::LOGIN_ATTEMPT_WINDOW) {
                    return true;
                } else {
                    // Window expired, clear attempts
                    unset($_SESSION[$lockoutKey]);
                    return false;
                }
            }
        }
        return false;
    }
    
    /**
     * Record a failed login attempt
     */
    private function recordFailedLogin($username) {
        $this->initSession();
        $lockoutKey = 'login_attempts_' . md5($username);
        
        if (!isset($_SESSION[$lockoutKey])) {
            $_SESSION[$lockoutKey] = [
                'count' => 1,
                'first_attempt' => time(),
            ];
        } else {
            $_SESSION[$lockoutKey]['count']++;
        }
    }
    
    /**
     * Clear failed login attempts for a user
     */
    private function clearFailedLogins($username) {
        $this->initSession();
        $lockoutKey = 'login_attempts_' . md5($username);
        unset($_SESSION[$lockoutKey]);
    }
    
    /**
     * Require authentication (call at start of protected pages)
     */
    public function requireLogin() {
        if (!$this->isAuthenticated()) {
            header('Location: ' . APP_URL . '/public/login.php');
            exit;
        }
    }
    
    /**
     * Require superuser role
     */
    public function requireSuper() {
        $this->requireLogin();
        if (!$this->isSuper()) {
            http_response_code(403);
            die('Access denied. Superuser privileges required.');
        }
    }
    
    /**
     * Validate CSRF token (for POST requests)
     * @param string $token Token from POST data
     */
    public function validateCsrf($token) {
        if (!SecurityUtil::validateCsrfToken($token)) {
            throw new Exception("CSRF token validation failed");
        }
        return true;
    }
    
    /**
     * Get CSRF token for forms
     */
    public function getCsrfToken() {
        $this->initSession();
        return SecurityUtil::createCsrfToken();
    }
}
