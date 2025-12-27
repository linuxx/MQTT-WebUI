<?php
/**
 * Admin - Audit Logs
 */

require_once __DIR__ . '/../../includes/bootstrap.php';

$auth->requireSuper();

$auditLogger = new AuditLogger();

// Pagination
$page = (int)($_GET['page'] ?? 1);
$perPage = 50;
$offset = ($page - 1) * $perPage;

// Filtering
$filters = [];
$action = $_GET['action'] ?? '';
if (!empty($action)) {
    $filters['action'] = $action;
}

$entity_type = $_GET['entity_type'] ?? '';
if (!empty($entity_type)) {
    $filters['entity_type'] = $entity_type;
}

// Get logs and total count
$totalLogs = $auditLogger->countAuditLogs($filters);
$logs = $auditLogger->getAuditLogs($filters, $perPage, $offset);
$totalPages = ceil($totalLogs / $perPage);

$actionOptions = [
    'login' => 'Login',
    'logout' => 'Logout',
    'failed_login' => 'Failed Login',
    'user_created' => 'User Created',
    'user_deleted' => 'User Deleted',
    'user_role_changed' => 'Role Changed',
    'user_enabled' => 'User Enabled',
    'user_disabled' => 'User Disabled',
    'password_changed' => 'Password Changed',
    'acl_created' => 'ACL Created',
    'acl_updated' => 'ACL Updated',
    'acl_deleted' => 'ACL Deleted',
    'api_key_created' => 'API Key Created',
    'api_key_revoked' => 'API Key Revoked',
    'api_key_granted' => 'API Key Granted',
    'api_key_deleted' => 'API Key Deleted',
    'api_publish' => 'API Publish',
];

$entityOptions = [
    'auth' => 'Authentication',
    'user' => 'User',
    'acl' => 'ACL',
    'api_key' => 'API Key',
];

$actionBadgeMap = [
    'created' => 'text-bg-success',
    'deleted' => 'text-bg-danger',
    'revoked' => 'text-bg-danger',
    'granted' => 'text-bg-success',
    'updated' => 'text-bg-warning',
    'changed' => 'text-bg-warning',
    'enabled' => 'text-bg-success',
    'disabled' => 'text-bg-secondary',
    'failed' => 'text-bg-danger',
    'login' => 'text-bg-primary',
    'logout' => 'text-bg-secondary',
];

$entityBadgeMap = [
    'auth' => 'text-bg-primary',
    'user' => 'text-bg-info',
    'acl' => 'text-bg-warning',
    'api_key' => 'text-bg-success',
];

$pageTitle = 'Audit Logs';
$pageHeading = 'Audit Logs';
$activeNav = 'audit-logs';
$baseUrl = rtrim(APP_URL, '/');

require_once __DIR__ . '/../../includes/header.php';
?>

<div class="card shadow-sm">
    <div class="card-body">
        <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-3">
            <h2 class="h5 mb-0">Audit Logs (Total: <?php echo $totalLogs; ?>)</h2>
            <a href="?" class="btn btn-sm btn-outline-secondary">Clear Filter</a>
        </div>

        <form method="GET" class="row g-2 mb-3">
            <div class="col-12 col-md-4">
                <label for="action" class="form-label">Action</label>
                <select id="action" name="action" class="form-select">
                    <option value="">All Actions</option>
                    <?php foreach ($actionOptions as $value => $label): ?>
                        <option value="<?php echo htmlspecialchars($value); ?>" <?php echo $action === $value ? 'selected' : ''; ?>><?php echo htmlspecialchars($label); ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-12 col-md-4">
                <label for="entity_type" class="form-label">Entity Type</label>
                <select id="entity_type" name="entity_type" class="form-select">
                    <option value="">All Entity Types</option>
                    <?php foreach ($entityOptions as $value => $label): ?>
                        <option value="<?php echo htmlspecialchars($value); ?>" <?php echo $entity_type === $value ? 'selected' : ''; ?>><?php echo htmlspecialchars($label); ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <div class="col-12 col-md-4 d-flex align-items-end">
                <button type="submit" class="btn btn-primary">Filter</button>
            </div>
        </form>

        <div class="table-responsive">
            <table class="table table-sm table-hover">
                <thead class="table-light">
                    <tr>
                        <th>Timestamp</th>
                        <th>User</th>
                        <th>Action</th>
                        <th>Entity</th>
                        <th>Description</th>
                        <th>IP Address</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($logs)): ?>
                        <tr>
                            <td colspan="6" class="text-center text-muted py-4">No audit logs found</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($logs as $log): ?>
                            <tr>
                                <td class="text-muted small"><?php echo htmlspecialchars(date('Y-m-d H:i:s', strtotime($log['created_at']))); ?></td>
                                <td><?php $username = $log['username'] ?? ''; echo htmlspecialchars($username ?: ($log['user_id'] ? 'User #' . $log['user_id'] : 'System')); ?></td>
                                <td>
                                    <?php
                                        $actionText = $actionOptions[$log['action']] ?? ucwords(str_replace('_', ' ', $log['action']));
                                        $badgeClass = 'text-bg-secondary';
                                        foreach ($actionBadgeMap as $key => $class) {
                                            if (strpos($log['action'], $key) !== false) {
                                                $badgeClass = $class;
                                                break;
                                            }
                                        }
                                    ?>
                                    <span class="badge <?php echo $badgeClass; ?>">
                                        <?php echo htmlspecialchars($actionText); ?>
                                    </span>
                                </td>
                                <td>
                                    <?php
                                        $entityText = $entityOptions[$log['entity_type']] ?? ucfirst($log['entity_type']);
                                        $entityClass = $entityBadgeMap[$log['entity_type']] ?? 'text-bg-secondary';
                                    ?>
                                    <span class="badge <?php echo $entityClass; ?>">
                                        <?php echo htmlspecialchars($entityText); ?>
                                    </span>
                                </td>
                                <td><?php echo htmlspecialchars(substr($log['description'], 0, 80)); ?></td>
                                <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

        <?php if ($totalPages > 1): ?>
            <nav class="d-flex justify-content-center mt-3">
                <ul class="pagination pagination-sm mb-0">
                    <?php if ($page > 1): ?>
                        <li class="page-item"><a class="page-link" href="?page=1<?php echo $action ? '&action=' . urlencode($action) : ''; ?><?php echo $entity_type ? '&entity_type=' . urlencode($entity_type) : ''; ?>">First</a></li>
                        <li class="page-item"><a class="page-link" href="?page=<?php echo $page - 1; ?><?php echo $action ? '&action=' . urlencode($action) : ''; ?><?php echo $entity_type ? '&entity_type=' . urlencode($entity_type) : ''; ?>">Prev</a></li>
                    <?php endif; ?>

                    <?php for ($i = max(1, $page - 2); $i <= min($totalPages, $page + 2); $i++): ?>
                        <?php if ($i === $page): ?>
                            <li class="page-item active"><span class="page-link"><?php echo $i; ?></span></li>
                        <?php else: ?>
                            <li class="page-item"><a class="page-link" href="?page=<?php echo $i; ?><?php echo $action ? '&action=' . urlencode($action) : ''; ?><?php echo $entity_type ? '&entity_type=' . urlencode($entity_type) : ''; ?>"><?php echo $i; ?></a></li>
                        <?php endif; ?>
                    <?php endfor; ?>

                    <?php if ($page < $totalPages): ?>
                        <li class="page-item"><a class="page-link" href="?page=<?php echo $page + 1; ?><?php echo $action ? '&action=' . urlencode($action) : ''; ?><?php echo $entity_type ? '&entity_type=' . urlencode($entity_type) : ''; ?>">Next</a></li>
                        <li class="page-item"><a class="page-link" href="?page=<?php echo $totalPages; ?><?php echo $action ? '&action=' . urlencode($action) : ''; ?><?php echo $entity_type ? '&entity_type=' . urlencode($entity_type) : ''; ?>">Last</a></li>
                    <?php endif; ?>
                </ul>
            </nav>
        <?php endif; ?>
    </div>
</div>

<?php require_once __DIR__ . '/../../includes/footer.php'; ?>


