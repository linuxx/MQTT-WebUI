<?php
/**
 * Admin - Manage Users
 */
require_once __DIR__ . '/../../includes/bootstrap.php';

$auth->requireSuper();

$userManager = new UserManager();
$aclManager = new AclManager();
$error = '';
$success = '';
$action = $_GET['action'] ?? '';
$currentUserId = (int)$auth->getUserId();
$passwordRules = [];
$minLength = defined('PASSWORD_MIN_LENGTH') ? (int)PASSWORD_MIN_LENGTH : 8;
$passwordRules[] = "Min {$minLength} chars";
if (defined('PASSWORD_REQUIRE_UPPERCASE') && PASSWORD_REQUIRE_UPPERCASE) {
    $passwordRules[] = 'Uppercase';
}
if (defined('PASSWORD_REQUIRE_LOWERCASE') && PASSWORD_REQUIRE_LOWERCASE) {
    $passwordRules[] = 'Lowercase';
}
if (defined('PASSWORD_REQUIRE_NUMBERS') && PASSWORD_REQUIRE_NUMBERS) {
    $passwordRules[] = 'Number';
}
if (defined('PASSWORD_REQUIRE_SYMBOLS') && PASSWORD_REQUIRE_SYMBOLS) {
    $passwordRules[] = 'Symbol';
}
$passwordHelpText = implode(', ', $passwordRules);

// Handle user creation
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'create') {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception("CSRF validation failed");
        }

        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        $email = $_POST['email'] ?? '';
        $isAdmin = !empty($_POST['is_super']);

        $userManager->createUser($username, $password, $email, $isAdmin);
        $success = "User created successfully";

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle user deletion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'delete') {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception("CSRF validation failed");
        }

        $userId = (int)$_POST['user_id'];
        $userManager->deleteUser($userId);
        $success = "User deleted successfully";

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle user role change
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'role') {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception("CSRF validation failed");
        }

        $userId = (int)$_POST['user_id'];
        $isAdmin = (bool)($_POST['is_super'] ?? false);

        $userManager->setAdminStatus($userId, $isAdmin);
        $success = "User role updated";

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle enable/disable
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'toggle') {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception("CSRF validation failed");
        }

        $userId = (int)$_POST['user_id'];
        $isEnabled = (bool)($_POST['is_enabled'] ?? false);

        $userManager->setUserEnabled($userId, $isEnabled);
        $success = "User status updated";

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle user edit
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'edit') {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception("CSRF validation failed");
        }

        $userId = (int)$_POST['user_id'];
        if ($userId === $currentUserId) {
            throw new Exception("You cannot edit your own user");
        }

        $user = $userManager->getUserById($userId);
        if (!$user) {
            throw new Exception("User not found");
        }

        $email = $_POST['email'] ?? '';
        $isEnabled = !empty($_POST['is_enabled']);
        $isAdmin = !empty($_POST['is_super']);

        $userManager->updateUser($userId, ['email' => $email]);

        if ((bool)$user['is_enabled'] !== $isEnabled) {
            $userManager->setUserEnabled($userId, $isEnabled);
        }
        if ((bool)$user['is_super'] !== $isAdmin) {
            $userManager->setAdminStatus($userId, $isAdmin);
        }

        $success = "User updated successfully";

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle password reset
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'reset_password') {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception("CSRF validation failed");
        }

        $userId = (int)$_POST['user_id'];
        if ($userId === $currentUserId) {
            throw new Exception("You cannot reset your own password here");
        }

        $newPassword = $_POST['new_password'] ?? '';
        $confirmPassword = $_POST['confirm_password'] ?? '';
        if ($newPassword === '') {
            throw new Exception("Password is required");
        }
        if ($newPassword !== $confirmPassword) {
            throw new Exception("Password confirmation does not match");
        }

        $userManager->resetPassword($userId, $newPassword);
        $success = "Password reset successfully";

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Get all users
$users = $userManager->getAllUsers();

$pageTitle = 'Manage Users';
$pageHeading = 'Manage Users';
$activeNav = 'users';
$baseUrl = rtrim(APP_URL, '/');

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
        <h2 class="h5 mb-3">Create New User</h2>
        <form method="POST" action="?action=create">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">

            <div class="row g-3">
                <div class="col-12 col-md-4">
                    <label for="username" class="form-label">Username</label>
                    <input type="text" id="username" name="username" class="form-control" required placeholder="e.g., john_doe">
                </div>
                <div class="col-12 col-md-4">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" id="password" name="password" class="form-control" required placeholder="Min 12 chars, upper, lower, number, symbol">
                    <div class="form-text"><?php echo htmlspecialchars($passwordHelpText); ?></div>
                </div>
                <div class="col-12 col-md-4">
                    <label for="email" class="form-label">Email (optional)</label>
                    <input type="email" id="email" name="email" class="form-control" placeholder="user@example.com">
                </div>
            </div>

            <div class="form-check my-3">
                <input type="checkbox" id="is_super" name="is_super" value="1" class="form-check-input">
                <label for="is_super" class="form-check-label">Make Superuser</label>
            </div>

            <button type="submit" class="btn btn-primary">Create User</button>
        </form>
    </div>
</div>

<div class="card shadow-sm">
    <div class="card-body">
        <h2 class="h5 mb-3">All Users (<?php echo count($users); ?>)</h2>
        <div class="table-responsive">
            <table class="table table-sm table-hover align-middle">
                <thead class="table-light">
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Status</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $user): ?>
                        <tr>
                            <td><strong><?php echo htmlspecialchars($user['username']); ?></strong></td>
                            <td><?php echo htmlspecialchars($user['email'] ?? '-'); ?></td>
                            <td>
                                <?php if ($user['is_super']): ?>
                                    <span class="badge text-bg-warning">Admin</span>
                                <?php else: ?>
                                    <span class="text-muted">User</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if (!$user['is_enabled']): ?>
                                    <span class="badge text-bg-danger">Disabled</span>
                                <?php else: ?>
                                    <span class="badge text-bg-success">Enabled</span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo htmlspecialchars(date('Y-m-d', strtotime($user['created_at']))); ?></td>
                            <td>
                                <?php $isSelf = ((int)$user['id'] === $currentUserId); ?>
                                <div class="d-flex flex-wrap gap-1">
                                    <?php if ($isSelf): ?>
                                        <button type="button" class="btn btn-sm btn-outline-primary" disabled>Edit</button>
                                        <button type="button" class="btn btn-sm btn-outline-secondary" disabled>Reset Password</button>
                                    <?php else: ?>
                                        <button type="button" class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#editUserModal-<?php echo (int)$user['id']; ?>">Edit</button>
                                        <button type="button" class="btn btn-sm btn-outline-secondary" data-bs-toggle="modal" data-bs-target="#resetPasswordModal-<?php echo (int)$user['id']; ?>">Reset Password</button>
                                    <?php endif; ?>

                                    <?php if ($isSelf): ?>
                                        <button type="button" class="btn btn-sm btn-warning" disabled><?php echo $user['is_super'] ? 'Demote' : 'Promote'; ?></button>
                                    <?php elseif ($user['is_super']): ?>
                                        <button type="button" class="btn btn-sm btn-warning" data-bs-toggle="modal" data-bs-target="#roleModal-<?php echo (int)$user['id']; ?>">Demote</button>
                                    <?php else: ?>
                                        <button type="button" class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#roleModal-<?php echo (int)$user['id']; ?>">Promote</button>
                                    <?php endif; ?>

                                    <?php if ($isSelf): ?>
                                        <button type="button" class="btn btn-sm btn-outline-warning" disabled><?php echo $user['is_enabled'] ? 'Disable' : 'Enable'; ?></button>
                                    <?php elseif ($user['is_enabled']): ?>
                                        <button type="button" class="btn btn-sm btn-outline-warning" data-bs-toggle="modal" data-bs-target="#toggleModal-<?php echo (int)$user['id']; ?>">Disable</button>
                                    <?php else: ?>
                                        <button type="button" class="btn btn-sm btn-outline-success" data-bs-toggle="modal" data-bs-target="#toggleModal-<?php echo (int)$user['id']; ?>">Enable</button>
                                    <?php endif; ?>

                                    <?php if ($isSelf): ?>
                                        <button type="button" class="btn btn-sm btn-outline-danger" disabled>Delete</button>
                                    <?php else: ?>
                                        <button type="button" class="btn btn-sm btn-outline-danger" data-bs-toggle="modal" data-bs-target="#deleteModal-<?php echo (int)$user['id']; ?>">Delete</button>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        <?php if (!$isSelf): ?>
                            <div class="modal fade" id="editUserModal-<?php echo (int)$user['id']; ?>" tabindex="-1" aria-hidden="true">
                                <div class="modal-dialog">
                                    <div class="modal-content">
                                        <form method="POST" action="?action=edit">
                                            <div class="modal-header">
                                                <h5 class="modal-title">Edit User</h5>
                                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                            </div>
                                            <div class="modal-body">
                                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
                                                <input type="hidden" name="user_id" value="<?php echo (int)$user['id']; ?>">

                                                <div class="mb-3">
                                                    <label class="form-label">Username</label>
                                                    <input type="text" class="form-control" value="<?php echo htmlspecialchars($user['username']); ?>" readonly>
                                                </div>
                                                <div class="mb-3">
                                                    <label for="email-<?php echo (int)$user['id']; ?>" class="form-label">Email</label>
                                                    <input type="email" id="email-<?php echo (int)$user['id']; ?>" name="email" class="form-control" value="<?php echo htmlspecialchars($user['email'] ?? ''); ?>">
                                                </div>
                                                <div class="form-check mb-3">
                                                    <input type="checkbox" id="is_super-<?php echo (int)$user['id']; ?>" name="is_super" class="form-check-input" value="1" <?php echo $user['is_super'] ? 'checked' : ''; ?>>
                                                    <label for="is_super-<?php echo (int)$user['id']; ?>" class="form-check-label">Superuser</label>
                                                </div>
                                                <div class="form-check">
                                                    <input type="checkbox" id="is_enabled-<?php echo (int)$user['id']; ?>" name="is_enabled" class="form-check-input" value="1" <?php echo $user['is_enabled'] ? 'checked' : ''; ?>>
                                                    <label for="is_enabled-<?php echo (int)$user['id']; ?>" class="form-check-label">Enabled</label>
                                                </div>
                                            </div>
                                            <div class="modal-footer">
                                                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                                                <button type="submit" class="btn btn-primary">Save</button>
                                            </div>
                                        </form>
                                    </div>
                                </div>
                            </div>

                            <div class="modal fade" id="resetPasswordModal-<?php echo (int)$user['id']; ?>" tabindex="-1" aria-hidden="true">
                                <div class="modal-dialog">
                                    <div class="modal-content">
                                        <form method="POST" action="?action=reset_password">
                                            <div class="modal-header">
                                                <h5 class="modal-title">Reset Password</h5>
                                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                            </div>
                                            <div class="modal-body">
                                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
                                                <input type="hidden" name="user_id" value="<?php echo (int)$user['id']; ?>">

                                                <div class="mb-3">
                                                    <label for="new_password_<?php echo (int)$user['id']; ?>" class="form-label">New Password</label>
                                                    <input type="password" id="new_password_<?php echo (int)$user['id']; ?>" name="new_password" class="form-control" required>
                                                    <div class="form-text"><?php echo htmlspecialchars($passwordHelpText); ?></div>
                                                </div>
                                                <div class="mb-3">
                                                    <label for="confirm_password_<?php echo (int)$user['id']; ?>" class="form-label">Confirm New Password</label>
                                                    <input type="password" id="confirm_password_<?php echo (int)$user['id']; ?>" name="confirm_password" class="form-control" required>
                                                </div>
                                            </div>
                                            <div class="modal-footer">
                                                <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                                                <button type="submit" class="btn btn-danger">Reset Password</button>
                                            </div>
                                        </form>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>

                        <div class="modal fade" id="roleModal-<?php echo (int)$user['id']; ?>" tabindex="-1" aria-hidden="true">
                            <div class="modal-dialog">
                                <div class="modal-content">
                                    <form method="POST" action="?action=role">
                                        <div class="modal-header">
                                            <h5 class="modal-title"><?php echo $user['is_super'] ? 'Demote User' : 'Promote User'; ?></h5>
                                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                        </div>
                                        <div class="modal-body">
                                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
                                            <input type="hidden" name="user_id" value="<?php echo (int)$user['id']; ?>">
                                            <input type="hidden" name="is_super" value="<?php echo $user['is_super'] ? '0' : '1'; ?>">
                                            <?php if (!$user['is_super']): ?>
                                                <div class="alert alert-danger">
                                                    Promoting to superuser will remove all custom ACLs for this user and replace them with a wildcard ACL (<code>#</code>).
                                                </div>
                                            <?php endif; ?>
                                            <?php if ($user['is_super']): ?>
                                                Demote <strong><?php echo htmlspecialchars($user['username']); ?></strong> from superuser?
                                            <?php else: ?>
                                                Promote <strong><?php echo htmlspecialchars($user['username']); ?></strong> to superuser?
                                            <?php endif; ?>
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                                            <button type="submit" class="btn btn-warning">Confirm</button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>

                        <div class="modal fade" id="toggleModal-<?php echo (int)$user['id']; ?>" tabindex="-1" aria-hidden="true">
                            <div class="modal-dialog">
                                <div class="modal-content">
                                    <form method="POST" action="?action=toggle">
                                        <div class="modal-header">
                                            <h5 class="modal-title"><?php echo $user['is_enabled'] ? 'Disable User' : 'Enable User'; ?></h5>
                                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                        </div>
                                        <div class="modal-body">
                                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
                                            <input type="hidden" name="user_id" value="<?php echo (int)$user['id']; ?>">
                                            <input type="hidden" name="is_enabled" value="<?php echo $user['is_enabled'] ? '0' : '1'; ?>">
                                            <?php if ($user['is_enabled']): ?>
                                                Disable <strong><?php echo htmlspecialchars($user['username']); ?></strong>?
                                            <?php else: ?>
                                                Enable <strong><?php echo htmlspecialchars($user['username']); ?></strong>?
                                            <?php endif; ?>
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                                            <button type="submit" class="btn btn-outline-warning">Confirm</button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>

                        <div class="modal fade" id="deleteModal-<?php echo (int)$user['id']; ?>" tabindex="-1" aria-hidden="true">
                            <div class="modal-dialog">
                                <div class="modal-content">
                                    <form method="POST" action="?action=delete">
                                        <div class="modal-header">
                                            <h5 class="modal-title">Delete User</h5>
                                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                        </div>
                                        <div class="modal-body">
                                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
                                            <input type="hidden" name="user_id" value="<?php echo (int)$user['id']; ?>">
                                            Delete <strong><?php echo htmlspecialchars($user['username']); ?></strong>? This cannot be undone.
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
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../../includes/footer.php'; ?>

