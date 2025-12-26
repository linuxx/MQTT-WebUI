<?php
/**
 * Admin - Manage API Keys
 */

require_once __DIR__ . '/../../includes/bootstrap.php';

$auth->requireSuper();

$apiKeyManager = new ApiKeyManager();
$error = '';
$success = '';

// Handle API key revocation
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['revoke_key'])) {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception("CSRF validation failed");
        }

        $keyId = (int)$_POST['key_id'];
        $apiKeyManager->revokeApiKey($keyId);
        $success = "API key revoked successfully";

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle API key grant
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['grant_key'])) {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception("CSRF validation failed");
        }

        $keyId = (int)$_POST['key_id'];
        $apiKeyManager->grantApiKey($keyId);
        $success = "API key granted successfully";

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle API key deletion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['delete_key'])) {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception("CSRF validation failed");
        }

        $keyId = (int)$_POST['key_id'];
        $apiKeyManager->deleteApiKey($keyId);
        $success = "API key deleted successfully";

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Get all API keys
$apiKeys = $apiKeyManager->getAllApiKeys();

$pageTitle = 'Manage API Keys';
$pageHeading = 'Manage API Keys';
$activeNav = 'api-keys';
$baseUrl = rtrim(APP_URL, '/');

require_once __DIR__ . '/../../includes/header.php';
?>

<?php if ($error): ?>
    <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
<?php endif; ?>

<?php if ($success): ?>
    <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
<?php endif; ?>

<div class="card shadow-sm">
    <div class="card-body">
        <div class="alert alert-info">
            <strong>API Keys Overview:</strong> Users create API keys to publish MQTT messages via HTTP. Keys are shown only once at creation time. This page shows all keys in the system and their status.
        </div>

        <h2 class="h5 mb-3">All API Keys (<?php echo count($apiKeys); ?>)</h2>
        <div class="table-responsive">
            <table class="table table-sm table-hover align-middle">
                <thead class="table-light">
                    <tr>
                        <th>User</th>
                        <th>Allowed Topic</th>
                        <th>Status</th>
                        <th>Last Used</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($apiKeys)): ?>
                        <tr>
                            <td colspan="6" class="text-center text-muted py-3">No API keys created</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($apiKeys as $key): ?>
                            <tr>
                                <td><strong><?php echo htmlspecialchars($key['username']); ?></strong></td>
                                <td><code><?php echo htmlspecialchars($key['allowed_topic']); ?></code></td>
                                <td>
                                    <?php if ($key['is_enabled']): ?>
                                        <span class="badge text-bg-success">Active</span>
                                    <?php else: ?>
                                        <span class="badge text-bg-secondary">Revoked</span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo $key['last_used_at'] ? htmlspecialchars(date('Y-m-d H:i', strtotime($key['last_used_at']))) : '-'; ?></td>
                                <td><?php echo htmlspecialchars(date('Y-m-d', strtotime($key['created_at']))); ?></td>
                                <td>
                                    <?php if ($key['is_enabled']): ?>
                                        <form method="POST" class="d-inline">
                                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
                                            <input type="hidden" name="revoke_key" value="1">
                                            <input type="hidden" name="key_id" value="<?php echo $key['id']; ?>">
                                            <button type="submit" class="btn btn-sm btn-outline-danger" onclick="return confirm('Revoke this API key?')">Revoke</button>
                                        </form>
                                        <button type="button" class="btn btn-sm btn-outline-secondary ms-1" data-bs-toggle="modal" data-bs-target="#deleteKeyModal-<?php echo (int)$key['id']; ?>">Delete</button>
                                    <?php else: ?>
                                        <form method="POST" class="d-inline">
                                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
                                            <input type="hidden" name="grant_key" value="1">
                                            <input type="hidden" name="key_id" value="<?php echo $key['id']; ?>">
                                            <button type="submit" class="btn btn-sm btn-outline-success">Grant</button>
                                        </form>
                                        <button type="button" class="btn btn-sm btn-outline-secondary ms-1" data-bs-toggle="modal" data-bs-target="#deleteKeyModal-<?php echo (int)$key['id']; ?>">Delete</button>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <div class="modal fade" id="deleteKeyModal-<?php echo (int)$key['id']; ?>" tabindex="-1" aria-hidden="true">
                                <div class="modal-dialog">
                                    <div class="modal-content">
                                        <form method="POST">
                                            <div class="modal-header">
                                                <h5 class="modal-title">Delete API Key</h5>
                                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                            </div>
                                            <div class="modal-body">
                                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
                                                <input type="hidden" name="delete_key" value="1">
                                                <input type="hidden" name="key_id" value="<?php echo (int)$key['id']; ?>">
                                                Delete API key for <strong><?php echo htmlspecialchars($key['username']); ?></strong> on topic <code><?php echo htmlspecialchars($key['allowed_topic']); ?></code>? This cannot be undone.
                                            </div>
                                            <div class="modal-footer">
                                                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                                                <button type="submit" class="btn btn-danger">Delete</button>
                                            </div>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../../includes/footer.php'; ?>

