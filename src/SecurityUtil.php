<?php
/**
 * SecurityUtil
 *
 * PBKDF2 password hashing and verification
 * Compatible with mosquitto-auth-plug
 * PHP 8+
 */

final class SecurityUtil
{
    private const TAG = 'PBKDF2';
    private const SEPARATOR = '$';

    private const HASH_ALGORITHM = 'sha256';
    private const ITERATIONS = 901;
    private const SALT_BYTE_SIZE = 12;
    private const HASH_BYTE_SIZE = 24;

    /**
     * Create a PBKDF2 hash
     *
     * Format:
     * PBKDF2$sha256$901$<base64(salt)>$<base64(hash)>
     */
    public static function createPassword(string $password): string
    {
        // Delegate to hashPassword which uses configured PBKDF2 constants
        return self::hashPassword($password);
    }

    /**
     * Verify a password against a stored PBKDF2 hash
     *
     * This is the method your CLI test should call
     */
    public static function verifyPassword(string $password, string $storedHash): bool
    {
        return self::verifyHash($password, $storedHash);
    }

    /**
     * Internal verification logic
     */
    private static function verifyHash(string $password, string $stored): bool
    {
        $parts = explode(self::SEPARATOR, $stored);
        if (count($parts) !== 5) {
            return false;
        }

        [$tag, $algorithm, $iterations, $saltB64, $hashB64] = $parts;

        if ($tag !== self::TAG) {
            return false;
        }

        // Restore padding for base64 values that may have been stripped
        $pad = function (string $s): string {
            $mod = strlen($s) % 4;
            if ($mod === 0) {
                return $s;
            }
            return $s . str_repeat('=', 4 - $mod);
        };

        $saltPadded = $pad($saltB64);
        $expected = base64_decode($pad($hashB64), true);

        if ($expected === false) {
            return false;
        }

        // Use the base64 salt string (padded) when deriving to match genhash8.php
        $derived = self::pbkdf2(
            $algorithm,
            $password,
            $saltPadded,
            (int)$iterations,
            strlen($expected),
            true
        );

        return hash_equals($expected, $derived);
    }


    public function requireAdmin() {
        $this->requireLogin();
        if (!$this->isSuper()) {
            http_response_code(403);
            die('Access denied. Admin privileges required.');
        }
    }


    /**
     * PBKDF2 implementation
     *
     * Uses native hash_pbkdf2 when available
     */
    private static function pbkdf2(
        string $algorithm,
        string $password,
        string $salt,
        int $iterations,
        int $keyLength,
        bool $rawOutput = false
    ): string {
        $algorithm = strtolower($algorithm);

        if (!in_array($algorithm, hash_algos(), true)) {
            throw new RuntimeException('Invalid hash algorithm');
        }

        if ($iterations <= 0 || $keyLength <= 0) {
            throw new RuntimeException('Invalid PBKDF2 parameters');
        }

        if (function_exists('hash_pbkdf2')) {
            if (!$rawOutput) {
                $keyLength *= 2;
            }

            return hash_pbkdf2(
                $algorithm,
                $password,
                $salt,
                $iterations,
                $keyLength,
                $rawOutput
            );
        }

        // Manual fallback (kept for completeness)
        $hashLength = strlen(hash($algorithm, '', true));
        $blockCount = (int)ceil($keyLength / $hashLength);
        $output = '';

        for ($i = 1; $i <= $blockCount; $i++) {
            $last = $salt . pack('N', $i);
            $xorsum = $last = hash_hmac($algorithm, $last, $password, true);

            for ($j = 1; $j < $iterations; $j++) {
                $xorsum ^= ($last = hash_hmac($algorithm, $last, $password, true));
            }

            $output .= $xorsum;
        }

        $result = substr($output, 0, $keyLength);
        return $rawOutput ? $result : bin2hex($result);
    }

    /**
     * Basic input sanitizer (removes control chars and trims)
     */
    public static function sanitize(string $value): string
    {
        $val = trim($value);
        // Strip low ASCII control characters
        $val = filter_var($val, FILTER_UNSAFE_RAW, FILTER_FLAG_STRIP_LOW);
        return $val;
    }

    /**
     * Username validation: returns array of error messages (empty if ok)
     */
    public static function validateUsername(string $username): array
    {
        $errors = [];
        $len = strlen($username);
        if ($len < 3 || $len > 32) {
            $errors[] = 'Username must be between 3 and 32 characters';
        }
        if (!preg_match('/^[A-Za-z0-9_.-]+$/', $username)) {
            $errors[] = 'Username contains invalid characters';
        }
        return $errors;
    }

    /**
     * Password validation: minimal rules, returns array of errors
     */
    public static function validatePassword(string $password): array
    {
        $errors = [];
        $minLength = defined('PASSWORD_MIN_LENGTH') ? (int)PASSWORD_MIN_LENGTH : 8;
        $requireUpper = defined('PASSWORD_REQUIRE_UPPERCASE') ? (bool)PASSWORD_REQUIRE_UPPERCASE : true;
        $requireLower = defined('PASSWORD_REQUIRE_LOWERCASE') ? (bool)PASSWORD_REQUIRE_LOWERCASE : true;
        $requireNumbers = defined('PASSWORD_REQUIRE_NUMBERS') ? (bool)PASSWORD_REQUIRE_NUMBERS : true;
        $requireSymbols = defined('PASSWORD_REQUIRE_SYMBOLS') ? (bool)PASSWORD_REQUIRE_SYMBOLS : false;

        if (strlen($password) < $minLength) {
            $errors[] = "Password must be at least {$minLength} characters long";
        }
        if ($requireNumbers && !preg_match('/[0-9]/', $password)) {
            $errors[] = 'Password must contain at least one digit';
        }
        if ($requireLower && !preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain at least one lowercase letter';
        }
        if ($requireUpper && !preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter';
        }
        if ($requireSymbols && !preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = 'Password must contain at least one symbol';
        }
        return $errors;
    }

    /**
     * Email validation
     */
    public static function validateEmail(string $email): array
    {
        $errors = [];
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Invalid email address';
        }
        if (strlen($email) > 254) {
            $errors[] = 'Email address is too long';
        }
        return $errors;
    }

    /**
     * MQTT topic validation (allows wildcards and %u placeholder)
     */
    public static function validateMqttTopic(string $topic): array
    {
        $errors = [];
        $topic = trim($topic);

        if ($topic === '') {
            $errors[] = 'Topic is required';
            return $errors;
        }

        if (strlen($topic) > 255) {
            $errors[] = 'Topic is too long';
        }

        if (preg_match('/[\x00-\x1F\x7F]/', $topic)) {
            $errors[] = 'Topic contains invalid control characters';
        }

        $allowed = preg_match('/^[A-Za-z0-9_\\-\\/\\+\\#%\\.]+$/', $topic);
        if (!$allowed) {
            $errors[] = 'Topic contains invalid characters';
        }

        return $errors;
    }

    /**
     * Alias for createPassword (keeps older API)
     */
    public static function hashPassword(string $password): string
    {
        $iterations = defined('PBKDF2_ITERATIONS') ? PBKDF2_ITERATIONS : self::ITERATIONS;
        $algo = defined('PBKDF2_HASH_ALGO') ? PBKDF2_HASH_ALGO : self::HASH_ALGORITHM;
        $saltBytes = defined('PBKDF2_SALT_BYTES') ? PBKDF2_SALT_BYTES : self::SALT_BYTE_SIZE;
        $derivedBytes = defined('PBKDF2_DERIVED_KEY_BYTES') ? PBKDF2_DERIVED_KEY_BYTES : self::HASH_BYTE_SIZE;

        // Create a base64-encoded salt string (matches genhash8.php)
        $salt_raw = random_bytes($saltBytes);
        $salt_b64 = base64_encode($salt_raw);

        // Use the base64 salt string when deriving the key (genhash8 uses the string)
        $derived = hash_pbkdf2(
            $algo,
            $password,
            $salt_b64,
            $iterations,
            $derivedBytes,
            true
        );

        $hash_b64 = base64_encode($derived);

        return self::TAG . self::SEPARATOR . $algo . self::SEPARATOR . $iterations
            . self::SEPARATOR . $salt_b64 . self::SEPARATOR . $hash_b64;
    }

    /**
     * Generate a random API key string
     */
    public static function generateApiKey(): string
    {
        $length = defined('API_KEY_LENGTH') ? API_KEY_LENGTH : 32;
        $length = max(16, (int)$length);

        $bytes = (int)ceil($length / 2);
        $key = bin2hex(random_bytes($bytes));

        return substr($key, 0, $length);
    }

    /**
     * Hash an API key for storage/lookup
     */
    public static function hashApiKey(string $plainKey): string
    {
        return hash('sha256', $plainKey);
    }

    /**
     * Determine if stored hash needs rehash based on algorithm/iterations
     */
    public static function passwordNeedsRehash(string $storedHash): bool
    {
        $parts = explode(self::SEPARATOR, $storedHash);
        if (count($parts) !== 5) {
            return true;
        }

        [$tag, $algorithm, $iterations] = $parts;
        if ($tag !== self::TAG) {
            return true;
        }
        if (strtolower($algorithm) !== strtolower(self::HASH_ALGORITHM)) {
            return true;
        }
        if ((int)$iterations !== self::ITERATIONS) {
            return true;
        }
        return false;
    }

    /**
     * CSRF token helpers
     */
    public static function createCsrfToken(): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['csrf_token_time'] = time();
        }
        return $_SESSION['csrf_token'];
    }

    public static function validateCsrfToken(?string $token): bool
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        if (empty($token) || empty($_SESSION['csrf_token'])) {
            return false;
        }
        // Optional expiry (1 hour)
        if (!empty($_SESSION['csrf_token_time']) && (time() - $_SESSION['csrf_token_time']) > 3600) {
            unset($_SESSION['csrf_token']);
            unset($_SESSION['csrf_token_time']);
            return false;
        }
        return hash_equals($_SESSION['csrf_token'], $token);
    }

    /**
     * Client info helpers
     */
    public static function getClientIp(): string
    {
        $ip = '';
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $arr = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $ip = trim($arr[0]);
        } elseif (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return substr($ip, 0, 45);
    }

    public static function getUserAgent(): string
    {
        return isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 255) : '';
    }
}
