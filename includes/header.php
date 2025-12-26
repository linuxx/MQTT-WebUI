<?php
if (!isset($pageTitle)) {
    $pageTitle = APP_NAME;
}
if (!isset($pageHeading)) {
    $pageHeading = $pageTitle;
}
$activeNav = $activeNav ?? '';
$showNav = $showNav ?? true;
if (!isset($baseUrl)) {
    $baseUrl = rtrim(APP_URL, '/');
}

$isAuthenticated = isset($auth) && $auth->isAuthenticated();
$isAdmin = $isAuthenticated && $auth->isSuper();
$username = $isAuthenticated ? $auth->getUsername() : '';
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

function navActive($key, $activeNav)
{
    return $key === $activeNav ? ' active' : '';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($pageTitle); ?> - <?php echo htmlspecialchars(APP_NAME); ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #f5f5f5; }
        .navbar-brand { font-weight: 600; }
        .table code { font-size: 0.85em; }
    </style>
</head>
<body>
<?php if ($showNav && $isAuthenticated): ?>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container">
        <a class="navbar-brand" href="<?php echo $baseUrl; ?>/public/user/dashboard.php">
            <?php echo htmlspecialchars(APP_NAME); ?>
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#mainNavbar" aria-controls="mainNavbar" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="mainNavbar">
            <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                <?php if ($isAdmin): ?>
                    <li class="nav-item"><a class="nav-link<?php echo navActive('dashboard', $activeNav); ?>" href="<?php echo $baseUrl; ?>/public/user/dashboard.php">Dashboard</a></li>
                    <li class="nav-item"><a class="nav-link<?php echo navActive('users', $activeNav); ?>" href="<?php echo $baseUrl; ?>/public/admin/users.php">Users</a></li>
                    <li class="nav-item"><a class="nav-link<?php echo navActive('acls', $activeNav); ?>" href="<?php echo $baseUrl; ?>/public/admin/acls.php">ACLs</a></li>
                    <li class="nav-item"><a class="nav-link<?php echo navActive('api-keys', $activeNav); ?>" href="<?php echo $baseUrl; ?>/public/admin/api-keys.php">API Keys</a></li>
                    <li class="nav-item"><a class="nav-link<?php echo navActive('audit-logs', $activeNav); ?>" href="<?php echo $baseUrl; ?>/public/admin/audit-logs.php">Audit Logs</a></li>
                <?php else: ?>
                    <li class="nav-item"><a class="nav-link<?php echo navActive('dashboard', $activeNav); ?>" href="<?php echo $baseUrl; ?>/public/user/dashboard.php">Dashboard</a></li>
                <?php endif; ?>
            </ul>
            <div class="d-flex align-items-center gap-3">
                <?php if ($username): ?>
                    <div class="dropdown">
                        <button class="btn btn-outline-light btn-sm dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <?php echo htmlspecialchars($username); ?>
                        </button>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li><button class="dropdown-item" type="button" data-bs-toggle="modal" data-bs-target="#changePasswordModal">Change Password</button></li>
                            <li><hr class="dropdown-divider"></li>
                            <li><a class="dropdown-item" href="<?php echo $baseUrl; ?>/public/logout.php">Logout</a></li>
                        </ul>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</nav>
<?php endif; ?>
<main class="container py-4">
<?php if (!empty($_SESSION['flash_error'])): ?>
    <div class="alert alert-danger">
        <?php echo htmlspecialchars($_SESSION['flash_error']); ?>
    </div>
    <?php unset($_SESSION['flash_error']); ?>
<?php endif; ?>
<?php if (!empty($_SESSION['flash_success'])): ?>
    <div class="alert alert-success">
        <?php echo htmlspecialchars($_SESSION['flash_success']); ?>
    </div>
    <?php unset($_SESSION['flash_success']); ?>
<?php endif; ?>
<?php if (!empty($pageHeading)): ?>
    <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mb-3">
        <h1 class="h3 mb-0"><?php echo htmlspecialchars($pageHeading); ?></h1>
        <?php if (!empty($pageActions)) { echo $pageActions; } ?>
    </div>
<?php endif; ?>

<?php if ($showNav && $isAuthenticated): ?>
<div class="modal fade" id="changePasswordModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <form method="POST">
                <div class="modal-header">
                    <h5 class="modal-title">Change Password</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
                    <input type="hidden" name="change_password" value="1">

                    <div class="mb-3">
                        <label for="current_password" class="form-label">Current Password</label>
                        <input type="password" class="form-control" id="current_password" name="current_password" required>
                    </div>
                    <div class="mb-3">
                        <label for="new_password" class="form-label">New Password</label>
                        <input type="password" class="form-control" id="new_password" name="new_password" required>
                        <div class="form-text"><?php echo htmlspecialchars($passwordHelpText); ?></div>
                    </div>
                    <div class="mb-3">
                        <label for="confirm_password" class="form-label">Confirm New Password</label>
                        <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-primary">Update Password</button>
                </div>
            </form>
        </div>
    </div>
</div>
<?php endif; ?>
