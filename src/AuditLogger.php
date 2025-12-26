<?php
/**
 * Audit logging system
 * Tracks all security-relevant actions
 */

class AuditLogger {
    
    private $db;
    
    public function __construct() {
        $this->db = Database::getInstance();
    }
    
    /**
     * Log an action
     * @param string $action Action type (e.g., 'login', 'user_created', 'acl_updated')
     * @param string $entityType Type of entity affected ('user', 'acl', 'api_key', 'auth')
     * @param int|null $entityId ID of affected entity
     * @param string $description Human-readable description
     * @param int|null $userId User performing the action (defaults to current user)
     */
    public function log(
        $action,
        $entityType,
        $entityId = null,
        $description = '',
        $userId = null
    ) {
        try {
            // Use current user if not specified
            if ($userId === null && isset($_SESSION['user_id'])) {
                $userId = $_SESSION['user_id'];
            }
            
            $ip = SecurityUtil::getClientIp();
            $userAgent = SecurityUtil::getUserAgent();
            
            $this->db->insert('tbAuditLogs', [
                'user_id' => $userId,
                'action' => substr($action, 0, 100),
                'entity_type' => substr($entityType, 0, 50),
                'entity_id' => $entityId,
                'description' => $description,
                'ip_address' => $ip,
                'user_agent' => $userAgent,
            ]);
        } catch (Exception $e) {
            error_log('Audit logging failed: ' . $e->getMessage());
        }
    }
    
    /**
     * Log successful login
     */
    public function logLogin($userId, $username) {
        $this->log('login', 'auth', $userId, "User '$username' logged in", $userId);
    }
    
    /**
     * Log failed login attempt
     */
    public function logFailedLogin($username) {
        $this->log('failed_login', 'auth', null, "Failed login attempt for username '$username'");
    }
    
    /**
     * Log logout
     */
    public function logLogout($userId, $username) {
        $this->log('logout', 'auth', $userId, "User '$username' logged out", $userId);
    }
    
    /**
     * Log user creation
     */
    public function logUserCreated($userId, $newUsername, $isAdmin = false) {
        $this->log(
            'user_created',
            'user',
            $userId,
            "User '$newUsername' created" . ($isAdmin ? ' (admin)' : ''),
            null
        );
    }
    
    /**
     * Log user deletion
     */
    public function logUserDeleted($username) {
        $this->log('user_deleted', 'user', null, "User '$username' deleted");
    }
    
    /**
     * Log password change
     */
    public function logPasswordChanged($userId, $username) {
        $this->log('password_changed', 'user', $userId, "Password changed for user '$username'", $userId);
    }
    
    /**
     * Log user role change
     */
    public function logUserRoleChanged($userId, $username, $isAdmin) {
        $role = $isAdmin ? 'admin' : 'user';
        $this->log(
            'user_role_changed',
            'user',
            $userId,
            "User '$username' role changed to '$role'",
            null
        );
    }
    
    /**
     * Log ACL change
     */
    public function logAclChanged($aclId, $userId, $topic, $rw, $action = 'updated') {
        $rwText = $rw == 1 ? 'read' : ($rw == 2 ? 'write' : 'read/write');
        $this->log(
            'acl_' . $action,
            'acl',
            $aclId,
            "ACL $action for user ID $userId on topic '$topic' ($rwText)"
        );
    }
    
    /**
     * Log API key creation
     */
    public function logApiKeyCreated($keyId, $userId, $topic, $username = null) {
        $userLabel = $username ? "user '$username'" : "user ID $userId";
        $this->log(
            'api_key_created',
            'api_key',
            $keyId,
            "API key created for $userLabel on topic '$topic'",
            $userId
        );
    }
    
    /**
     * Log API key revocation
     */
    public function logApiKeyRevoked($keyId, $userId, $topic = null, $username = null) {
        $userLabel = $username ? "user '$username'" : "user ID $userId";
        $topicLabel = $topic ? " on topic '$topic'" : '';
        $this->log(
            'api_key_revoked',
            'api_key',
            $keyId,
            "API key revoked for $userLabel$topicLabel",
            $userId
        );
    }

    public function logApiKeyDeleted($keyId, $userId, $topic = null, $username = null) {
        $userLabel = $username ? "user '$username'" : "user ID $userId";
        $topicLabel = $topic ? " on topic '$topic'" : '';
        $this->log(
            'api_key_deleted',
            'api_key',
            $keyId,
            "API key deleted for $userLabel$topicLabel",
            $userId
        );
    }

    public function logApiKeyGranted($keyId, $userId, $topic = null, $username = null) {
        $userLabel = $username ? "user '$username'" : "user ID $userId";
        $topicLabel = $topic ? " on topic '$topic'" : '';
        $this->log(
            'api_key_granted',
            'api_key',
            $keyId,
            "API key granted for $userLabel$topicLabel",
            $userId
        );
    }
    
    /**
     * Get audit logs with filters
     */
    public function getAuditLogs($filters = [], $limit = 100, $offset = 0) {
        $query = 'SELECT tbAuditLogs.*, tbUsers.username AS username FROM tbAuditLogs LEFT JOIN tbUsers ON tbUsers.id = tbAuditLogs.user_id WHERE 1=1';
        $params = [];
        
        if (!empty($filters['action'])) {
            $query .= ' AND action = ?';
            $params[] = $filters['action'];
        }
        
        if (!empty($filters['user_id'])) {
            $query .= ' AND user_id = ?';
            $params[] = $filters['user_id'];
        }
        
        if (!empty($filters['entity_type'])) {
            $query .= ' AND entity_type = ?';
            $params[] = $filters['entity_type'];
        }
        
        $query .= ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        $params[] = $limit;
        $params[] = $offset;
        
        return $this->db->fetchAll($query, $params);
    }
    
    /**
     * Count audit logs
     */
    public function countAuditLogs($filters = []) {
        $query = 'SELECT COUNT(*) as count FROM tbAuditLogs WHERE 1=1';
        $params = [];
        
        if (!empty($filters['action'])) {
            $query .= ' AND action = ?';
            $params[] = $filters['action'];
        }
        
        if (!empty($filters['user_id'])) {
            $query .= ' AND user_id = ?';
            $params[] = $filters['user_id'];
        }
        
        if (!empty($filters['entity_type'])) {
            $query .= ' AND entity_type = ?';
            $params[] = $filters['entity_type'];
        }
        
        $result = $this->db->fetchOne($query, $params);
        return $result['count'] ?? 0;
    }
}

