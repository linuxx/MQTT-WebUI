<?php
/**
 * Database abstraction layer using PDO
 * All database operations use prepared statements
 */

class Database {
    private static $instance = null;
    private $pdo;
    private $lastQuery = '';
    
    private function __construct() {
        try {
            $dsn = 'mysql:host=' . DB_HOST . ':' . DB_PORT . ';dbname=' . DB_NAME . ';charset=utf8mb4';
            
            $this->pdo = new PDO(
                $dsn,
                DB_USER,
                DB_PASS,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,  // Use real prepared statements
                ]
            );
            
            // Set session variables for timezone
            $this->pdo->exec("SET NAMES utf8mb4");
            $this->pdo->exec("SET time_zone = '+00:00'");
            
        } catch (PDOException $e) {
            // Log error but don't expose details to user
            error_log('Database connection failed: ' . $e->getMessage());
            throw new Exception('Database connection failed');
        }
    }
    
    /**
     * Get singleton instance of database
     */
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Execute a prepared statement
     * @param string $query SQL query with ? placeholders
     * @param array $params Parameters to bind
     * @return PDOStatement
     */
    public function query($query, $params = []) {
        try {
            $this->lastQuery = $query;
            $stmt = $this->pdo->prepare($query);
            $stmt->execute($params);
            return $stmt;
        } catch (PDOException $e) {
            error_log('Database query failed: ' . $e->getMessage());
            error_log('Query: ' . $query);
            throw new Exception('Database query failed');
        }
    }
    
    /**
     * Fetch single row
     */
    public function fetchOne($query, $params = []) {
        $stmt = $this->query($query, $params);
        return $stmt->fetch();
    }
    
    /**
     * Fetch all rows
     */
    public function fetchAll($query, $params = []) {
        $stmt = $this->query($query, $params);
        return $stmt->fetchAll();
    }
    
    /**
     * Insert and return last insert ID
     */
    public function insert($table, $data) {
        $columns = array_keys($data);
        $values = array_values($data);
        $placeholders = array_fill(0, count($columns), '?');
        
        $query = sprintf(
            'INSERT INTO %s (%s) VALUES (%s)',
            $table,
            implode(', ', $columns),
            implode(', ', $placeholders)
        );
        
        $this->query($query, $values);
        return $this->pdo->lastInsertId();
    }
    
    /**
     * Update record
     */
    public function update($table, $data, $where, $whereParams = []) {
        $sets = [];
        $values = [];
        
        foreach ($data as $key => $value) {
            $sets[] = $key . ' = ?';
            $values[] = $value;
        }
        
        $values = array_merge($values, $whereParams);
        
        $query = sprintf(
            'UPDATE %s SET %s WHERE %s',
            $table,
            implode(', ', $sets),
            $where
        );
        
        $stmt = $this->query($query, $values);
        return $stmt->rowCount();
    }
    
    /**
     * Delete record
     */
    public function delete($table, $where, $params = []) {
        $query = sprintf('DELETE FROM %s WHERE %s', $table, $where);
        $stmt = $this->query($query, $params);
        return $stmt->rowCount();
    }
    
    /**
     * Count records
     */
    public function count($table, $where = '', $params = []) {
        $query = 'SELECT COUNT(*) as count FROM ' . $table;
        if ($where) {
            $query .= ' WHERE ' . $where;
        }
        $result = $this->fetchOne($query, $params);
        return $result['count'] ?? 0;
    }
    
    /**
     * Begin transaction
     */
    public function beginTransaction() {
        return $this->pdo->beginTransaction();
    }
    
    /**
     * Commit transaction
     */
    public function commit() {
        return $this->pdo->commit();
    }
    
    /**
     * Rollback transaction
     */
    public function rollback() {
        return $this->pdo->rollBack();
    }
    
    /**
     * Get raw PDO for advanced operations
     */
    public function getPDO() {
        return $this->pdo;
    }
}
