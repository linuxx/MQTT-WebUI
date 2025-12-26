<?php
/**
 * Admin - Edit User (reset password, view details)
 */

require_once __DIR__ . '/../../includes/bootstrap.php';

$auth->requireSuper();

$userManager = new UserManager();
$aclManager = new AclManager();
$apiKeyManager = new ApiKeyManager();

$userId = (int)($_GET['id'] ?? 0);
$user = $userManager->getUserById($userId);

if (!$user) {
    die('User not found');
}

$error = '';
$success = '';

// Handle password reset
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['reset_password'])) {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception("CSRF validation failed");
        }

        $newPassword = $_POST['new_password'] ?? '';

        if (empty($newPassword)) {
            throw new Exception("Password is required");
        }

        $userManager->resetPassword($userId, $newPassword);
        $success = "Password reset successfully";

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Get user's ACLs and API keys
$acls = $aclManager->getAclsByUserId($userId);
$apiKeys = $apiKeyManager->getApiKeysByUserId($userId);

$pageTitle = 'Edit User';
$pageHeading = 'Edit User: ' . $user['username'];
$activeNav = 'users';
$baseUrl = rtrim(APP_URL, '/');
$pageActions = '<a class="btn btn-sm btn-outline-secondary" href="' . $baseUrl . '/public/admin/users.php">Back to Users</a>';

require_once __DIR__ . '/../../includes/header.php';
?>

<?php if ($error): ?>
    <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
<?php endif; ?>

<?php if ($success): ?>
    <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
<?php endif; ?>

<div class="card shadow-sm mb-4">
    <div class="card-body">
        <h2 class="h5 mb-3">User Details</h2>
        <div class="row g-3">
            <div class="col-12 col-md-4">
                <div class="text-muted text-uppercase small">Username</div>
                <div><?php echo htmlspecialchars($user['username']); ?></div>
            </div>
            <div class="col-12 col-md-4">
                <div class="text-muted text-uppercase small">Email</div>
                <div><?php echo htmlspecialchars($user['email'] ?? '-'); ?></div>
            </div>
            <div class="col-12 col-md-4">
                <div class="text-muted text-uppercase small">Role</div>
                <div><?php echo $user['is_super'] ? 'Superuser' : 'User'; ?></div>
            </div>
            <div class="col-12 col-md-4">
                <div class="text-muted text-uppercase small">Status</div>
                <div><?php echo $user['is_enabled'] ? 'Enabled' : 'Disabled'; ?></div>
            </div>
            <div class="col-12 col-md-4">
                <div class="text-muted text-uppercase small">Created</div>
                <div><?php echo htmlspecialchars(date('Y-m-d H:i', strtotime($user['created_at']))); ?></div>
            </div>
            <div class="col-12 col-md-4">
                <div class="text-muted text-uppercase small">Password Changed</div>
                <div><?php echo htmlspecialchars(date('Y-m-d H:i', strtotime($user['password_changed_at']))); ?></div>
            </div>
        </div>
    </div>
</div>

<div class="card shadow-sm mb-4">
    <div class="card-body">
        <h2 class="h5 mb-3">Reset Password</h2>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
            <input type="hidden" name="reset_password" value="1">

            <div class="mb-3">
                <label for="new_password" class="form-label">New Password</label>
                <input type="password" id="new_password" name="new_password" class="form-control" required placeholder="Min 12 chars, upper, lower, number, symbol">
            </div>

            <button type="submit" class="btn btn-primary">Reset Password</button>
        </form>
    </div>
</div>

<div class="card shadow-sm mb-4">
    <div class="card-body">
        <h2 class="h5 mb-3">MQTT ACLs (<?php echo count($acls); ?>)</h2>
        <div class="table-responsive">
            <table class="table table-sm table-hover">
                <thead class="table-light">
                    <tr>
                        <th>Topic</th>
                        <th>Permission</th>
                        <th>Created</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($acls)): ?>
                        <tr>
                            <td colspan="3" class="text-center text-muted py-3">No ACLs defined</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($acls as $acl): ?>
                            <tr>
                                <?php $displayTopic = str_replace('%u', $user['username'], $acl['topic']); ?>
                                <td><code><?php echo htmlspecialchars($displayTopic); ?></code></td>
                                <td><?php echo htmlspecialchars(AclManager::formatPermissions($acl['rw'])); ?></td>
                                <td><?php echo htmlspecialchars(date('Y-m-d', strtotime($acl['created_at']))); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div class="card shadow-sm">
    <div class="card-body">
        <h2 class="h5 mb-3">API Keys (<?php echo count($apiKeys); ?>)</h2>
        <div class="table-responsive">
            <table class="table table-sm table-hover">
                <thead class="table-light">
                    <tr>
                        <th>Topic</th>
                        <th>Status</th>
                        <th>Last Used</th>
                        <th>Created</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($apiKeys)): ?>
                        <tr>
                            <td colspan="4" class="text-center text-muted py-3">No API keys created</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($apiKeys as $key): ?>
                            <tr>
                                <td><code><?php echo htmlspecialchars($key['allowed_topic']); ?></code></td>
                                <td><?php echo $key['is_enabled'] ? 'Active' : 'Revoked'; ?></td>
                                <td><?php echo $key['last_used_at'] ? htmlspecialchars(date('Y-m-d H:i', strtotime($key['last_used_at']))) : '-'; ?></td>
                                <td><?php echo htmlspecialchars(date('Y-m-d', strtotime($key['created_at']))); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../../includes/footer.php'; ?>


