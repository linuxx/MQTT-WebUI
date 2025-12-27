<?php
/**
 * ACL manager
 * Handles MQTT topic access control lists
 */

class AclManager {
    
    private $db;
    private $auditLogger;
    
    public function __construct() {
        $this->db = Database::getInstance();
        $this->auditLogger = new AuditLogger();
    }
    
    /**
     * Create ACL entry
     * @param int $userId
     * @param string $topic MQTT topic path
    * @param int $rw 1=read-only, 2=read/write
    */
    public function createAcl($userId, $topic, $rw = 2) {
        // Validate user exists
        $userManager = new UserManager();
        $user = $userManager->getUserById($userId);
        if (!$user) {
            throw new Exception("User not found");
        }
        
        // Validate topic
        $errors = SecurityUtil::validateMqttTopic($topic);
        if (!empty($errors)) {
            throw new Exception(implode('; ', $errors));
        }
        if (strpos($topic, '%') !== false) {
            throw new Exception("Topic cannot contain '%' placeholders");
        }
        
        // Validate rw value
        if (!in_array($rw, [1, 2])) {
            throw new Exception("Invalid read/write permission value");
        }
        
        // Resolve username and check if ACL already exists for this user/topic
        $username = $user['username'];
        $existing = $this->db->fetchOne(
            'SELECT id FROM tbACL WHERE username = ? AND topic = ?',
            [$username, $topic]
        );
        
        if ($existing) {
            throw new Exception("ACL already exists for this topic");
        }
        
        // Create ACL (store username per schema)
        $aclId = $this->db->insert('tbACL', [
            'username' => $username,
            'topic' => $topic,
            'rw' => $rw,
        ]);
        
        // Log action
        $this->auditLogger->logAclChanged($aclId, $userId, $topic, $rw, 'created', $username);
        
        return $aclId;
    }
    
    /**
     * Get ACL by ID
     */
    public function getAclById($aclId) {
        return $this->db->fetchOne(
            'SELECT id, username, topic, rw FROM tbACL WHERE id = ?',
            [$aclId]
        );
    }
    
    /**
     * Get all ACLs for a user
     */
    public function getAclsByUserId($userId) {
        // Resolve username and return ACLs
        $user = $this->db->fetchOne('SELECT username FROM tbUsers WHERE id = ?', [$userId]);
        if (!$user) {
            return [];
        }
        $username = $user['username'];

        return $this->db->fetchAll(
            'SELECT id, username, topic, rw FROM tbACL WHERE username = ? ORDER BY topic ASC',
            [$username]
        );
    }
    
    /**
     * Get all ACLs (for admin)
     */
    public function getAllAcls($limit = null, $offset = 0) {
        $query = 'SELECT tbACL.id, tbACL.username, tbACL.topic, tbACL.rw, tbUsers.super AS is_super FROM tbACL JOIN tbUsers ON tbACL.username = tbUsers.username ORDER BY tbACL.username ASC, tbACL.topic ASC';
        $params = [];
        
        if ($limit !== null) {
            $query .= ' LIMIT ? OFFSET ?';
            $params = [$limit, $offset];
        }
        
        return $this->db->fetchAll($query, $params);
    }
    
    /**
     * Count all ACLs
     */
    public function countAcls() {
        return $this->db->count('tbACL');
    }
    
    /**
     * Update ACL
     */
    public function updateAcl($aclId, $rw) {
        $acl = $this->getAclById($aclId);
        if (!$acl) {
            throw new Exception("ACL not found");
        }
        
        // Validate rw value
        if (!in_array($rw, [1, 2])) {
            throw new Exception("Invalid read/write permission value");
        }
        
        // Update
        $this->db->update('tbACL', ['rw' => $rw], 'id = ?', [$aclId]);

        // Log action (resolve user id from username)
        $userRec = $this->db->fetchOne('SELECT id FROM tbUsers WHERE username = ?', [$acl['username']]);
        $userId = $userRec['id'] ?? null;
        $this->auditLogger->logAclChanged($aclId, $userId, $acl['topic'], $rw, 'updated', $acl['username']);
        
        return true;
    }

    /**
     * Edit ACL topic and permission
     */
    public function editAcl($aclId, $topic, $rw) {
        $acl = $this->getAclById($aclId);
        if (!$acl) {
            throw new Exception("ACL not found");
        }

        $errors = SecurityUtil::validateMqttTopic($topic);
        if (!empty($errors)) {
            throw new Exception(implode('; ', $errors));
        }
        if (strpos($topic, '%') !== false) {
            throw new Exception("Topic cannot contain '%' placeholders");
        }

        if (!in_array($rw, [1, 2])) {
            throw new Exception("Invalid read/write permission value");
        }

        $this->db->update('tbACL', ['topic' => $topic, 'rw' => $rw], 'id = ?', [$aclId]);

        $userRec = $this->db->fetchOne('SELECT id FROM tbUsers WHERE username = ?', [$acl['username']]);
        $userId = $userRec['id'] ?? null;
        $this->auditLogger->logAclChanged($aclId, $userId, $topic, $rw, 'updated', $acl['username']);

        return true;
    }
    
    /**
     * Delete ACL
     */
    public function deleteAcl($aclId) {
        $acl = $this->getAclById($aclId);
        if (!$acl) {
            throw new Exception("ACL not found");
        }
        
        $rowsDeleted = $this->db->delete('tbACL', 'id = ?', [$aclId]);

        if ($rowsDeleted > 0) {
            $userRec = $this->db->fetchOne('SELECT id FROM tbUsers WHERE username = ?', [$acl['username']]);
            $userId = $userRec['id'] ?? null;
            $this->auditLogger->logAclChanged($aclId, $userId, $acl['topic'], $acl['rw'], 'deleted', $acl['username']);
        }
        
        return true;
    }
    
    /**
     * Get ACL by user and topic
     */
    public function getAclByUserAndTopic($userId, $topic) {
        $user = $this->db->fetchOne('SELECT username FROM tbUsers WHERE id = ?', [$userId]);
        if (!$user) {
            return null;
        }
        $username = $user['username'];

        return $this->db->fetchOne(
            'SELECT id, username, topic, rw FROM tbACL WHERE username = ? AND topic = ?',
            [$username, $topic]
        );
    }
    
    /**
     * Get read/write permission status for user on topic
     * @param int $userId
     * @param string $topic
     * @return array ['canRead' => bool, 'canWrite' => bool]
     */
    public function getUserTopicPermissions($userId, $topic) {
        $acl = $this->getAclByUserAndTopic($userId, $topic);
        
        if (!$acl) {
            return ['canRead' => false, 'canWrite' => false];
        }

        $rw = (int)$acl['rw'];

        return [
            'canRead' => $rw >= 1,
            'canWrite' => $rw >= 2,
        ];
    }
    
    /**
     * Get formatted read/write label
     */
    public static function formatPermissions($rw) {
        $rwInt = (int)$rw;

        if ($rwInt === 1) {
            return 'Read Only';
        }

        if ($rwInt >= 2) {
            return 'Read & Write';
        }

        return 'Unknown';
    }
}
