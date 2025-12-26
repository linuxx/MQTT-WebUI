<?php
declare(strict_types=1);
session_start();

/*
 * mosquitto-auth-plug compatible PBKDF2 generator
 * Iterations: 901 (unchanged)
 */

const PBKDF2_ALGO       = 'sha256';
const PBKDF2_ITERATIONS = 901;
const SALT_BYTES        = 12;
const KEY_BYTES         = 24;

function generate_mosquitto_hash(string $password): string
{
    $salt = base64_encode(random_bytes(SALT_BYTES));

    $dk = hash_pbkdf2(
        PBKDF2_ALGO,
        $password,
        $salt,                  // IMPORTANT: use salt as STRING
        PBKDF2_ITERATIONS,
        KEY_BYTES,
        true                    // raw output
    );

    return 'PBKDF2'
        . '$' . PBKDF2_ALGO
        . '$' . PBKDF2_ITERATIONS
        . '$' . $salt
        . '$' . base64_encode($dk);
}

$hash = null;
$sql = null;

// Handle form submit
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = $_POST['password'] ?? '';

    $_SESSION['last_password'] = $password;

    if ($password !== '') {
        $hash = generate_mosquitto_hash($password);
        $sql = "-- Create initial global admin (api_user)\n"
            . "INSERT INTO tbUsers (username, password, email, super, is_enabled, password_changed_at)\n"
            . "VALUES ('api_user', '{$hash}', NULL, 1, 1, NOW());\n\n"
            . "-- Ensure admin ACL for all topics\n"
            . "INSERT INTO tbACL (username, topic, rw)\n"
            . "SELECT 'api_user', '#', 3\n"
            . "WHERE NOT EXISTS (\n"
            . "  SELECT 1 FROM tbACL WHERE username = 'api_user' AND topic = '#'\n"
            . ");\n";
    }
}

// Restore last password
$lastPassword = $_SESSION['last_password'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>PBKDF2 Hash Generator (Mosquitto)</title>
    <style>
        body {
            font-family: system-ui, sans-serif;
            margin: 40px;
            max-width: 900px;
        }
        input[type=password], textarea {
            width: 100%;
            padding: 8px;
            font-family: monospace;
        }
        button {
            margin-top: 10px;
            padding: 8px 16px;
        }
        textarea {
            height: 140px;
        }
        .sql {
            height: 220px;
        }
    </style>
</head>
<body>

<h2>PBKDF2 Password Hash Generator</h2>

<form method="post">
    <label>
        Password:
        <input type="password" name="password" value="<?= htmlspecialchars($lastPassword) ?>" required>
    </label>

    <button type="submit">Generate Hash</button>
</form>

<?php if ($hash !== null): ?>
    <h3>Generated Hash</h3>
    <textarea readonly><?= htmlspecialchars($hash) ?></textarea>

    <h3>SQL to Create Initial Global Admin (api_user)</h3>
    <textarea class="sql" readonly><?= htmlspecialchars($sql ?? '') ?></textarea>
<?php endif; ?>

<p>
    Format:<br>
    <code>PBKDF2$sha256$901$salt$hash</code>
</p>

</body>
</html>