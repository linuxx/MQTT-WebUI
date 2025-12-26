<?php
/**
 * User manager
 * Handles user CRUD operations
 */

class UserManager {
    
    private $db;
    private $auditLogger;
    
    public function __construct() {
        $this->db = Database::getInstance();
        $this->auditLogger = new AuditLogger();
    }
    
    /**
     * Create a new user
     * @param string $username
     * @param string $password
     * @param string $email
     * @param bool $isAdmin
     * @return int User ID
     */
    public function createUser($username, $password, $email = '', $isAdmin = false) {
        // Validate inputs
        $errors = SecurityUtil::validateUsername($username);
        if (!empty($errors)) {
            throw new Exception(implode('; ', $errors));
        }
        
        $errors = SecurityUtil::validatePassword($password);
        if (!empty($errors)) {
            throw new Exception(implode('; ', $errors));
        }
        
        if (!empty($email)) {
            $errors = SecurityUtil::validateEmail($email);
            if (!empty($errors)) {
                throw new Exception(implode('; ', $errors));
            }
        }
        
        // Check if username already exists
        $existing = $this->db->fetchOne('SELECT id FROM tbUsers WHERE username = ?', [$username]);
        if ($existing) {
            throw new Exception("Username already exists");
        }
        
        // Hash password
        $passwordHash = SecurityUtil::hashPassword($password);
        
        // Create user
        $userId = $this->db->insert('tbUsers', [
            'username' => $username,
            'password' => $passwordHash,
            'email' => $email ?: null,
            'super' => $isAdmin ? 1 : 0,
            'is_enabled' => 1,
        ]);

        if ($isAdmin) {
            $adminTopic = '#';
            $adminAcl = $this->db->fetchOne(
                'SELECT id FROM tbACL WHERE username = ? AND topic = ?',
                [$username, $adminTopic]
            );
            if (!$adminAcl) {
                $this->db->insert('tbACL', [
                    'username' => $username,
                    'topic' => $adminTopic,
                    'rw' => 3,
                ]);
            }
        } else {
            $defaultTopic = '%u/#';
            $defaultAcl = $this->db->fetchOne(
                'SELECT id, rw FROM tbACL WHERE username = ? AND topic = ?',
                [$username, $defaultTopic]
            );
            if (!$defaultAcl) {
                $this->db->insert('tbACL', [
                    'username' => $username,
                    'topic' => $defaultTopic,
                    'rw' => 3,
                ]);
            } elseif ((int)$defaultAcl['rw'] !== 3) {
                $this->db->update('tbACL', ['rw' => 3], 'id = ?', [$defaultAcl['id']]);
            }
        }
        
        
        // Log action
        $this->auditLogger->logUserCreated($userId, $username, $isAdmin);
        
        return $userId;
    }
    
    /**
     * Get user by ID
     */
    public function getUserById($userId) {
        return $this->db->fetchOne(
            'SELECT id, username, email, super AS is_super, is_enabled, password_changed_at, created_at FROM tbUsers WHERE id = ?',
            [$userId]
        );
    }
    
    /**
     * Get user by username
     */
    public function getUserByUsername($username) {
        return $this->db->fetchOne(
            'SELECT id, username, email, super AS is_super, is_enabled, password_changed_at, created_at FROM tbUsers WHERE username = ?',
            [$username]
        );
    }
    
    /**
     * Get all users
     */
    public function getAllUsers($limit = null, $offset = 0) {
        $query = 'SELECT id, username, email, super AS is_super, is_enabled, password_changed_at, created_at FROM tbUsers ORDER BY username ASC';
        $params = [];
        
        if ($limit !== null) {
            $query .= ' LIMIT ? OFFSET ?';
            $params = [$limit, $offset];
        }
        
        return $this->db->fetchAll($query, $params);
    }
    
    /**
     * Count all users
     */
    public function countUsers() {
        return $this->db->count('tbUsers');
    }
    
    /**
     * Update user
     */
    public function updateUser($userId, $data) {
        // Validate email if provided
        if (isset($data['email']) && !empty($data['email'])) {
            $errors = SecurityUtil::validateEmail($data['email']);
            if (!empty($errors)) {
                throw new Exception(implode('; ', $errors));
            }
        }
        
        // Sanitize data
        $updateData = [];
        if (isset($data['email'])) {
            $updateData['email'] = $data['email'] ?: null;
        }
        if (isset($data['is_enabled'])) {
            $updateData['is_enabled'] = $data['is_enabled'] ? 1 : 0;
        }
        
        if (empty($updateData)) {
            return false;
        }
        
        return $this->db->update('tbUsers', $updateData, 'id = ?', [$userId]) > 0;
    }
    
    /**
     * Delete user
     */
    public function deleteUser($userId) {
        $user = $this->getUserById($userId);
        if (!$user) {
            throw new Exception("User not found");
        }
        
        $rowsDeleted = $this->db->delete('tbUsers', 'id = ?', [$userId]);
        
        if ($rowsDeleted > 0) {
            $this->auditLogger->logUserDeleted($user['username']);
        }
        
        return $rowsDeleted > 0;
    }
    
    /**
     * Change user password
     */
    public function changePassword($userId, $currentPassword, $newPassword) {
        // Validate new password
        $errors = SecurityUtil::validatePassword($newPassword);
        if (!empty($errors)) {
            throw new Exception(implode('; ', $errors));
        }
        
        // Get user
        $user = $this->db->fetchOne('SELECT password FROM tbUsers WHERE id = ?', [$userId]);
        if (!$user) {
            throw new Exception("User not found");
        }
        
        // Verify current password
        if (!SecurityUtil::verifyPassword($currentPassword, $user['password'])) {
            throw new Exception("Current password is incorrect");
        }
        
        
        // Hash new password
        $newHash = SecurityUtil::hashPassword($newPassword);
        
        // Update password
        $this->db->update(
            'tbUsers',
            ['password' => $newHash, 'password_changed_at' => date('Y-m-d H:i:s')],
            'id = ?',
            [$userId]
        );
        
        
        // Log action
        $userInfo = $this->getUserById($userId);
        $this->auditLogger->logPasswordChanged($userId, $userInfo['username']);
        
        return true;
    }
    
    /**
     * Admin reset user password
     */
    public function resetPassword($userId, $newPassword) {
        // Validate new password
        $errors = SecurityUtil::validatePassword($newPassword);
        if (!empty($errors)) {
            throw new Exception(implode('; ', $errors));
        }
        
        $user = $this->getUserById($userId);
        if (!$user) {
            throw new Exception("User not found");
        }
        
        // Hash new password
        $newHash = SecurityUtil::hashPassword($newPassword);
        
        // Update password
        $this->db->update(
            'tbUsers',
            ['password' => $newHash, 'password_changed_at' => date('Y-m-d H:i:s')],
            'id = ?',
            [$userId]
        );
        
        
        // Log action
        $this->auditLogger->logPasswordChanged($userId, $user['username']);
        
        return true;
    }
    
    /**
     * Set admin status
     */
    public function setAdminStatus($userId, $isAdmin) {
        $user = $this->getUserById($userId);
        if (!$user) {
            throw new Exception("User not found");
        }
        
        $this->db->update(
            'tbUsers',
            ['super' => $isAdmin ? 1 : 0],
            'id = ?',
            [$userId]
        );

        if ($isAdmin) {
            $this->db->delete('tbACL', 'username = ? AND topic NOT IN (?, ?)', [$user['username'], '%u/#', '#']);
            $this->db->delete('tbACL', 'username = ? AND topic = ?', [$user['username'], '%u/#']);
            $adminTopic = '#';
            $adminAcl = $this->db->fetchOne(
                'SELECT id FROM tbACL WHERE username = ? AND topic = ?',
                [$user['username'], $adminTopic]
            );
            if (!$adminAcl) {
                $this->db->insert('tbACL', [
                    'username' => $user['username'],
                    'topic' => $adminTopic,
                    'rw' => 3,
                ]);
            }
        } else {
            $this->db->delete('tbACL', 'username = ? AND topic = ?', [$user['username'], '#']);
            $defaultTopic = '%u/#';
            $defaultAcl = $this->db->fetchOne(
                'SELECT id FROM tbACL WHERE username = ? AND topic = ?',
                [$user['username'], $defaultTopic]
            );
            if (!$defaultAcl) {
                $this->db->insert('tbACL', [
                    'username' => $user['username'],
                    'topic' => $defaultTopic,
                    'rw' => 3,
                ]);
            }
        }
        
        $this->auditLogger->logUserRoleChanged($userId, $user['username'], $isAdmin);
        
        return true;
    }
    
    /**
     * Disable/enable user
     */
    public function setUserEnabled($userId, $isEnabled) {
        $user = $this->getUserById($userId);
        if (!$user) {
            throw new Exception("User not found");
        }
        
        $this->db->update(
            'tbUsers',
            ['is_enabled' => $isEnabled ? 1 : 0],
            'id = ?',
            [$userId]
        );
        
        $action = $isEnabled ? 'enabled' : 'disabled';
        $this->auditLogger->log(
            'user_' . $action,
            'user',
            $userId,
            "User '{$user['username']}' was $action"
        );
        
        return true;
    }

}
