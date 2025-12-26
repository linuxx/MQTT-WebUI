<?php
/**
 * API Key manager
 * Handles API key creation, revocation, and validation
 */

class ApiKeyManager {
    
    private $db;
    private $auditLogger;
    
    public function __construct() {
        $this->db = Database::getInstance();
        $this->auditLogger = new AuditLogger();
    }
    
    /**
     * Create new API key
     * @param int $userId
     * @param string $allowedTopic MQTT topic user can publish to
     * @return array ['key' => plaintext_key, 'keyHash' => hashed_key, 'id' => key_id]
     */
    public function createApiKey($userId, $allowedTopic, $allowAnyTopic = false) {
        // Validate user exists
        $userManager = new UserManager();
        $user = $userManager->getUserById($userId);
        if (!$user) {
            throw new Exception("User not found");
        }

        $username = $user['username'];
        $allowAnyTopic = (bool)$allowAnyTopic;

        if ($allowAnyTopic) {
            $allowedTopic = $username . '/#';
        } else {
            $allowedTopic = ltrim((string)$allowedTopic, '/');
            if ($allowedTopic === '') {
                throw new Exception("Topic is required");
            }

            if (strpos($allowedTopic, $username . '/') !== 0) {
                $allowedTopic = $username . '/' . $allowedTopic;
            }
        }
        
        // Validate topic
        $errors = SecurityUtil::validateMqttTopic($allowedTopic);
        if (!empty($errors)) {
            throw new Exception(implode('; ', $errors));
        }
        
        // Generate random key
        $plainKey = SecurityUtil::generateApiKey();
        $hashedKey = SecurityUtil::hashApiKey($plainKey);
        
        // Store hashed key
        $keyId = $this->db->insert('tbApiKeys', [
            'user_id' => $userId,
            'key_hash' => $hashedKey,
            'allowed_topic' => $allowedTopic,
            'allow_any_topic' => $allowAnyTopic ? 1 : 0,
            'is_enabled' => 1,
        ]);
        
        // Log action
        $this->auditLogger->logApiKeyCreated($keyId, $userId, $allowedTopic, $user['username']);
        
        return [
            'id' => $keyId,
            'key' => $plainKey,  // Only return once
            'keyHash' => $hashedKey,
            'allowedTopic' => $allowedTopic,
            'allowAnyTopic' => $allowAnyTopic,
        ];
    }
    
    /**
     * Validate API key
     * @param string $plainKey Plain API key
     * @return array|false Key data if valid, false otherwise
     */
    public function validateApiKey($plainKey) {
        if (empty($plainKey)) {
            return false;
        }
        
        // Hash the provided key
        $hashedKey = SecurityUtil::hashApiKey($plainKey);
        
        // Find matching key
        $key = $this->db->fetchOne(
            'SELECT tbApiKeys.id, tbApiKeys.user_id, tbUsers.username, tbApiKeys.allowed_topic, tbApiKeys.allow_any_topic, tbApiKeys.is_enabled FROM tbApiKeys JOIN tbUsers ON tbApiKeys.user_id = tbUsers.id WHERE tbApiKeys.key_hash = ? AND tbApiKeys.is_enabled = 1',
            [$hashedKey]
        );
        
        if (!$key) {
            return false;
        }
        
        // Verify user is enabled
        $user = $this->db->fetchOne('SELECT id, is_enabled FROM tbUsers WHERE id = ?', [$key['user_id']]);
        if (!$user || !$user['is_enabled']) {
            return false;
        }
        
        return $key;
    }
    
    /**
     * Get API key by ID (without revealing plaintext)
     */
    public function getApiKeyById($keyId) {
        return $this->db->fetchOne(
            'SELECT id, user_id, allowed_topic, allow_any_topic, is_enabled, last_used_at, created_at FROM tbApiKeys WHERE id = ?',
            [$keyId]
        );
    }
    
    /**
     * Get all API keys for a user
     */
    public function getApiKeysByUserId($userId) {
        return $this->db->fetchAll(
            'SELECT id, allowed_topic, allow_any_topic, is_enabled, last_used_at, created_at FROM tbApiKeys WHERE user_id = ? ORDER BY created_at DESC',
            [$userId]
        );
    }
    
    /**
     * Get all API keys (for admin)
     */
    public function getAllApiKeys($limit = null, $offset = 0) {
        $params = [];

        if ($limit !== null) {
            $params = [$limit, $offset];
            $limitClause = ' LIMIT ? OFFSET ?';
        } else {
            $limitClause = '';
        }

        $query = 'SELECT tbApiKeys.id, tbApiKeys.user_id, tbUsers.username, tbApiKeys.allowed_topic, tbApiKeys.is_enabled, tbApiKeys.last_used_at, tbApiKeys.created_at FROM tbApiKeys JOIN tbUsers ON tbApiKeys.user_id = tbUsers.id ORDER BY tbUsers.username ASC, tbApiKeys.created_at DESC' . $limitClause;
        return $this->db->fetchAll($query, $params);
    }
    
    /**
     * Count all API keys
     */
    public function countApiKeys() {
        return $this->db->count('tbApiKeys');
    }
    
    /**
     * Revoke API key
     */
    public function revokeApiKey($keyId) {
        $key = $this->getApiKeyById($keyId);
        if (!$key) {
            throw new Exception("API key not found");
        }
        
        $this->db->update('tbApiKeys', ['is_enabled' => 0], 'id = ?', [$keyId]);
        
        // Log action
        $userRec = $this->db->fetchOne('SELECT username FROM tbUsers WHERE id = ?', [$key['user_id']]);
        $this->auditLogger->logApiKeyRevoked($keyId, $key['user_id'], $key['allowed_topic'] ?? null, $userRec['username'] ?? null);
        
        return true;
    }
    
    /**
     * Update last_used_at timestamp
     */
    public function updateLastUsed($keyId) {
        return $this->db->update(
            'tbApiKeys',
            ['last_used_at' => date('Y-m-d H:i:s')],
            'id = ?',
            [$keyId]
        );
    }
    
    /**
     * Delete API key (hard delete)
     */
    public function deleteApiKey($keyId) {
        $key = $this->getApiKeyById($keyId);
        if (!$key) {
            throw new Exception("API key not found");
        }
        
        $rowsDeleted = $this->db->delete('tbApiKeys', 'id = ?', [$keyId]);
        
        if ($rowsDeleted > 0) {
            $userRec = $this->db->fetchOne('SELECT username FROM tbUsers WHERE id = ?', [$key['user_id']]);
            $this->auditLogger->logApiKeyDeleted($keyId, $key['user_id'], $key['allowed_topic'] ?? null, $userRec['username'] ?? null);
        }
        
        return true;
    }

    /**
     * Grant (re-enable) API key
     */
    public function grantApiKey($keyId) {
        $key = $this->getApiKeyById($keyId);
        if (!$key) {
            throw new Exception("API key not found");
        }

        $this->db->update('tbApiKeys', ['is_enabled' => 1], 'id = ?', [$keyId]);

        $userRec = $this->db->fetchOne('SELECT username FROM tbUsers WHERE id = ?', [$key['user_id']]);
        $this->auditLogger->logApiKeyGranted($keyId, $key['user_id'], $key['allowed_topic'] ?? null, $userRec['username'] ?? null);

        return true;
    }
}
