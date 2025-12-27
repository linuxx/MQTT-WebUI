<?php
/**
 * Admin - Manage ACLs
 */

require_once __DIR__ . '/../../includes/bootstrap.php';

$auth->requireSuper();

$userManager = new UserManager();
$aclManager = new AclManager();
$error = '';
$success = '';

// Handle ACL creation
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['create_acl'])) {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception("CSRF validation failed");
        }

        $userId = (int)$_POST['user_id'];
        $topic = $_POST['topic'] ?? '';
        $rw = (int)$_POST['rw'];

        $aclManager->createAcl($userId, $topic, $rw);
        $success = "ACL created successfully";

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle ACL deletion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['delete_acl'])) {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception("CSRF validation failed");
        }

        $aclId = (int)$_POST['acl_id'];
        $aclManager->deleteAcl($aclId);
        $success = "ACL deleted successfully";

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle ACL update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['update_acl'])) {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception("CSRF validation failed");
        }
        
        $aclId = (int)$_POST['acl_id'];
        $rw = (int)$_POST['rw'];
        
        $aclManager->updateAcl($aclId, $rw);
        $success = "ACL updated successfully";
        
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Handle ACL edit
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['edit_acl'])) {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception("CSRF validation failed");
        }

        $aclId = (int)$_POST['acl_id'];
        $topic = $_POST['topic'] ?? '';
        $rw = (int)$_POST['rw'];

        $aclManager->editAcl($aclId, $topic, $rw);
        $success = "ACL updated successfully";

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

// Get all users and ACLs
$users = $userManager->getAllUsers();
$acls = $aclManager->getAllAcls();

$pageTitle = 'Manage ACLs';
$pageHeading = 'Manage MQTT ACLs';
$activeNav = 'acls';
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
        <h2 class="h5 mb-3">Create New ACL</h2>
        <div class="alert alert-info">
            Default ACLs (<code>%u/#</code> and <code>#</code> for superusers) are inherited and cannot be deleted.
        </div>
        <div class="alert alert-secondary">
            <div class="d-flex justify-content-between align-items-center">
                <strong class="mb-0">Topic patterns and access</strong>
                <button class="btn btn-sm btn-outline-primary" type="button" data-bs-toggle="collapse" data-bs-target="#aclTopicHelp" aria-expanded="false" aria-controls="aclTopicHelp">
                    Show details
                </button>
            </div>
            <div class="collapse mt-3" id="aclTopicHelp">

                <p>
                MQTT topics are hierarchical, using <code>/</code> to separate levels.
                You can use wildcards to allow access to multiple related topics at once.
                </p>

                <strong><code>#</code> (multi-level wildcard)</strong>
                <p>
                Matches everything under a topic. This should be used carefully.
                </p>

                <div><code>sensors/#</code> allows access to:</div>
                <ul class="mb-2">
                <li><code>sensors</code></li>
                <li><code>sensors/room1</code></li>
                <li><code>sensors/room1/temperature</code></li>
                </ul>

                <strong><code>+</code> (single-level wildcard)</strong>
                <p>
                Matches exactly one level in the topic path.
                </p>

                <div><code>sensors/+/status</code> allows access to:</div>
                <ul class="mb-2">
                <li><code>sensors/device1/status</code></li>
                <li><code>sensors/device2/status</code></li>
                </ul>

                <div>Does <strong>not</strong> allow access to:</div>
                <ul class="mb-3">
                <li><code>sensors/device1/status/extra</code></li>
                </ul>

                <hr>

                <strong>Granting access to other users</strong>
                <p>
                Users only control topics under their own prefix. If <code>joe</code> needs to work with
                <code>bob</code>'s devices, add an ACL for user <code>joe</code> that points at Bob's topic tree.
                Grant the smallest scope that fits the job:
                </p>

                <div>Examples:</div>
                <ul class="mb-0">
                <li>
                    Only the <code>bob/device</code> topic: <code>bob/device</code>
                </li>
                <li>
                    Any topic Bob owns: <code>bob/#</code>
                </li>
                <li>
                    Just temperature topics on one level: <code>bob/+/temp</code>
                </li>
                </ul>

                <p class="mt-2 mb-0">
                <strong>Tip:</strong> Avoid using a single <code>#</code> unless you intend to grant full access.
                Narrow topic patterns are safer and easier to manage.
                </p>

            </div>
        </div>

        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
            <input type="hidden" name="create_acl" value="1">

            <div class="row g-3">
                <div class="col-12 col-md-4">
                    <label for="user_id" class="form-label">User</label>
                    <select id="user_id" name="user_id" class="form-select" required>
                        <option value="">Select user...</option>
                        <?php foreach ($users as $user): ?>
                            <?php if (!empty($user['is_super'])) { continue; } ?>
                            <option value="<?php echo $user['id']; ?>"><?php echo htmlspecialchars($user['username']); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>

                <div class="col-12 col-md-5">
                    <label for="topic" class="form-label">MQTT Topic</label>
                    <input type="text" id="topic" name="topic" class="form-control" required placeholder="e.g., home/temperature or sensors/#">
                    <div class="form-text">Use <code>+</code> or <code>#</code> only. Do not use <code>%</code> placeholders.</div>
                </div>

                <div class="col-12 col-md-3">
                    <label for="rw" class="form-label">Permission</label>
                    <select id="rw" name="rw" class="form-select" required>
                        <option value="1">Read Only</option>
                        <option value="2" selected>Read &amp; Write</option>
                    </select>
                </div>
            </div>

            <button type="submit" class="btn btn-primary mt-3">Create ACL</button>
        </form>
    </div>
</div>

<div class="card shadow-sm">
    <div class="card-body">
        <h2 class="h5 mb-3">All ACLs (<?php echo count($acls); ?>)</h2>
        <div class="table-responsive">
            <table class="table table-sm table-hover align-middle">
                <thead class="table-light">
                    <tr>
                        <th>User</th>
                        <th>Topic</th>
                        <th>Permission</th>
                        <th>Type</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($acls)): ?>
                        <tr>
                            <td colspan="4" class="text-center text-muted py-3">No ACLs defined</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($acls as $acl): ?>
                            <?php
                                $isInherited = ($acl['topic'] === '%u/#') || ($acl['topic'] === '#' && !empty($acl['is_super']));
                                $typeLabel = $isInherited ? 'Inherited' : 'Custom';
                                $permLabel = AclManager::formatPermissions($acl['rw']);
                                $permClass = ((int)$acl['rw'] === 1)
                                    ? 'text-bg-info'
                                    : (((int)$acl['rw'] >= 2) ? 'text-bg-success' : 'text-bg-secondary');
                            ?>
                            <tr>
                                <td><strong><?php echo htmlspecialchars($acl['username']); ?></strong></td>
                                <?php $displayTopic = str_replace('%u', $acl['username'], $acl['topic']); ?>
                                <td><code><?php echo htmlspecialchars($displayTopic); ?></code></td>
                                <td>
                                    <span class="badge <?php echo $permClass; ?>">
                                        <?php echo htmlspecialchars($permLabel); ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="badge <?php echo $isInherited ? 'text-bg-secondary' : 'text-bg-info'; ?>"><?php echo $typeLabel; ?></span>
                                </td>
                                <td>
                                    <?php if ($isInherited): ?>
                                        <button type="button" class="btn btn-sm btn-outline-secondary" disabled>Edit</button>
                                        <button type="button" class="btn btn-sm btn-outline-secondary" disabled>Delete</button>
                                    <?php else: ?>
                                        <button type="button" class="btn btn-sm btn-outline-primary" data-bs-toggle="modal" data-bs-target="#editAclModal-<?php echo (int)$acl['id']; ?>">Edit</button>
                                        <button type="button" class="btn btn-sm btn-outline-danger" data-bs-toggle="modal" data-bs-target="#deleteAclModal-<?php echo (int)$acl['id']; ?>">Delete</button>
                                    <?php endif; ?>
                                </td>
                            </tr>
                            <?php if (!$isInherited): ?>
                                <div class="modal fade" id="editAclModal-<?php echo (int)$acl['id']; ?>" tabindex="-1" aria-hidden="true">
                                    <div class="modal-dialog">
                                        <div class="modal-content">
                                            <form method="POST" class="d-inline">
                                                <div class="modal-header">
                                                    <h5 class="modal-title">Edit ACL</h5>
                                                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                                </div>
                                                <div class="modal-body">
                                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
                                                    <input type="hidden" name="edit_acl" value="1">
                                                    <input type="hidden" name="acl_id" value="<?php echo (int)$acl['id']; ?>">

                                                    <div class="mb-3">
                                                        <label class="form-label">User</label>
                                                        <input type="text" class="form-control" value="<?php echo htmlspecialchars($acl['username']); ?>" readonly>
                                                    </div>
                                                    <div class="mb-3">
                                                        <label for="topic-<?php echo (int)$acl['id']; ?>" class="form-label">Topic</label>
                                                        <input type="text" id="topic-<?php echo (int)$acl['id']; ?>" name="topic" class="form-control" value="<?php echo htmlspecialchars($acl['topic']); ?>" required>
                                                        <div class="form-text">Use <code>+</code> or <code>#</code> only. Do not use <code>%</code> placeholders.</div>
                                                    </div>
                                                    <div class="mb-3">
                                                        <label for="rw-<?php echo (int)$acl['id']; ?>" class="form-label">Permission</label>
                                                        <select id="rw-<?php echo (int)$acl['id']; ?>" name="rw" class="form-select" required>
                                                            <option value="1" <?php echo (int)$acl['rw'] === 1 ? 'selected' : ''; ?>>Read Only</option>
                                                            <option value="2" <?php echo (int)$acl['rw'] === 2 ? 'selected' : ''; ?>>Read &amp; Write</option>
                                                        </select>
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
                            <?php endif; ?>
                            <?php if (!$isInherited): ?>
                                <div class="modal fade" id="deleteAclModal-<?php echo (int)$acl['id']; ?>" tabindex="-1" aria-hidden="true">
                                    <div class="modal-dialog">
                                        <div class="modal-content">
                                            <form method="POST" class="d-inline">
                                                <div class="modal-header">
                                                    <h5 class="modal-title">Delete ACL</h5>
                                                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                                </div>
                                                <div class="modal-body">
                                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
                                                    <input type="hidden" name="delete_acl" value="1">
                                                    <input type="hidden" name="acl_id" value="<?php echo (int)$acl['id']; ?>">
                                                    Delete ACL for <strong><?php echo htmlspecialchars($acl['username']); ?></strong> on <code><?php echo htmlspecialchars($acl['topic']); ?></code>?
                                                </div>
                                                <div class="modal-footer">
                                                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                                                    <button type="submit" class="btn btn-danger">Delete</button>
                                                </div>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                            <?php endif; ?>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<?php require_once __DIR__ . '/../../includes/footer.php'; ?>

