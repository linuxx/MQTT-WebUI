<?php
/**
 * User Dashboard
 */

require_once __DIR__ . '/../../includes/bootstrap.php';

$auth->requireLogin();

$userId = $auth->getUserId();
$userManager = new UserManager();
$aclManager = new AclManager();
$apiKeyManager = new ApiKeyManager();

$user = $userManager->getUserById($userId);
$acls = $aclManager->getAclsByUserId($userId);
$apiKeys = $apiKeyManager->getApiKeysByUserId($userId);
$error = '';
$success = '';
$created = null;
$mqttHost = parse_url(APP_URL, PHP_URL_HOST) ?: MQTT_HOST;
$clearPortOpen = defined('MQTT_CLEAR_PORT_OPEN') ? (bool)MQTT_CLEAR_PORT_OPEN : true;
$clearPortNumber = defined('MQTT_CLEAR_PORT_NUMBER') ? (int)MQTT_CLEAR_PORT_NUMBER : MQTT_PORT;
$tlsPortOpen = defined('MQTT_TLS_PORT_OPEN') ? (bool)MQTT_TLS_PORT_OPEN : false;
$tlsPortNumber = defined('MQTT_TLS_PORT_NUMBER') ? (int)MQTT_TLS_PORT_NUMBER : 8883;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['create_api_key'])) {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception('CSRF validation failed');
        }

        $topic = $_POST['topic'] ?? '';
        $allowAnyTopic = !empty($_POST['allow_any_topic']);
        $topic = SecurityUtil::sanitize($topic);

        $created = $apiKeyManager->createApiKey($userId, $topic, $allowAnyTopic);
        $apiKeys = $apiKeyManager->getApiKeysByUserId($userId);

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['delete_api_key'])) {
    try {
        if (empty($_POST['csrf_token']) || !$auth->validateCsrf($_POST['csrf_token'])) {
            throw new Exception('CSRF validation failed');
        }

        $keyId = (int)($_POST['key_id'] ?? 0);
        $key = $apiKeyManager->getApiKeyById($keyId);
        if (!$key || (int)$key['user_id'] !== (int)$userId) {
            throw new Exception('API key not found');
        }

        $apiKeyManager->deleteApiKey($keyId);
        $success = 'API key deleted';
        $apiKeys = $apiKeyManager->getApiKeysByUserId($userId);

    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

$createdRelativeTopic = '';
if (!empty($created) && !empty($created['allowedTopic'])) {
    $createdRelativeTopic = $created['allowedTopic'];
    if (strpos($createdRelativeTopic, $user['username'] . '/') === 0) {
        $createdRelativeTopic = substr($createdRelativeTopic, strlen($user['username']) + 1);
    }
}

// For instruction panel, show first allowed topic (or wildcard)
$allowedTopic = $apiKeys[0]['allowed_topic'] ?? ($acls[0]['topic'] ?? '');

$pageTitle = 'Dashboard';
$pageHeading = 'Dashboard';
$activeNav = 'dashboard';
$baseUrl = rtrim(APP_URL, '/');

require_once __DIR__ . '/../../includes/header.php';
?>

<div class="row g-3 mb-4">
    <div class="col-12 col-lg-6">
        <div class="card shadow-sm h-100">
            <div class="card-body">
                <h2 class="h5 mb-2">Welcome, <?php echo htmlspecialchars($user['username']); ?></h2>
                <div class="text-muted">Your email: <?php echo htmlspecialchars($user['email'] ?? '-'); ?></div>
                <div class="text-muted">Role: <?php echo $user['is_super'] ? 'Superuser' : 'Standard User'; ?></div>
            </div>
        </div>
    </div>
    <div class="col-12 col-lg-6">
        <div class="card shadow-sm h-100">
            <div class="card-body">
                <h2 class="h5 mb-2">MQTT Connection</h2>
                <div class="mb-2">Host: <code><?php echo htmlspecialchars($mqttHost); ?></code></div>
                <?php if ($clearPortOpen): ?>
                    <div class="mb-2">Port: <code><?php echo htmlspecialchars((string)$clearPortNumber); ?></code></div>
                    <?php if ($tlsPortOpen): ?>
                        <div class="mb-2">TLS: <code>Optional</code> (Port <code><?php echo htmlspecialchars((string)$tlsPortNumber); ?></code>)</div>
                    <?php endif; ?>
                <?php else: ?>
                    <?php if ($tlsPortOpen): ?>
                        <div class="mb-2">TLS Port (required): <code><?php echo htmlspecialchars((string)$tlsPortNumber); ?></code></div>
                    <?php endif; ?>
                <?php endif; ?>
                <div class="text-muted small">Use your username and password from this portal to connect.</div>
            </div>
        </div>
    </div>
</div>

<div class="card shadow-sm mb-4">
    <div class="card-body">
        <h2 class="h5 mb-3">MQTT Permissions</h2>
        <div class="alert alert-info">
            <strong>Your MQTT topic access:</strong><br>
            You can publish messages to, and subscribe to messages from, any topic that starts with
            <code><?php echo htmlspecialchars($user['username']); ?>/</code>.<br><br>
            For example:
            <ul class="mb-0">
                <li><code><?php echo htmlspecialchars($user['username']); ?>/status</code></li>
                <li><code><?php echo htmlspecialchars($user['username']); ?>/devices/device1</code></li>
                <li><code><?php echo htmlspecialchars($user['username']); ?>/alerts/high</code></li>
            </ul>
            <br>
            This access is automatically enforced by the MQTT server, so you don’t need to configure anything yourself.
        </div>

        <?php if ($user['is_super']): ?>
            <div class="alert alert-warning">
                <strong>Superuser access:</strong><br>
                You have full access to the MQTT server. This means you can publish to and subscribe from
                <em>any</em> topic, including topics owned by other users.<br><br>
                Example topics you can access:
                <ul class="mb-0">
                    <li><code>bobross/device</code></li>
                    <li><code>alice/sensors/temperature</code></li>
                    <li><code>system/alerts</code></li>
                </ul>
            </div>

        <?php endif; ?>
        <?php if (empty($acls)): ?>
            <p class="text-muted mb-0">No MQTT permissions assigned. Contact your administrator.</p>
        <?php else: ?>
            <ul class="list-group list-group-flush">
                <?php foreach ($acls as $acl): ?>
                    <?php
                        $displayTopic = str_replace('%u', $user['username'], $acl['topic']);
                        $permLabel = AclManager::formatPermissions($acl['rw']);
                    ?>
                    <li class="list-group-item"><code><?php echo htmlspecialchars($displayTopic); ?></code> - <?php echo htmlspecialchars($permLabel); ?></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
    </div>
</div>

<div class="card shadow-sm mb-4">
    <div class="card-body">
        <h2 class="h5 mb-3">Your API Keys</h2>
        <p class="text-muted">API keys are write-only and can publish to their assigned topic. Keys are shown only once at creation.</p>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>
        <?php if (empty($apiKeys)): ?>
            <p class="text-muted">No API keys. Create one below.</p>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-sm table-hover align-middle">
                    <thead class="table-light">
                        <tr>
                            <th>Topic</th>
                            <th>Type</th>
                            <th>Status</th>
                            <th>Last Used</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($apiKeys as $k): ?>
                            <tr>
                                <td><code><?php echo htmlspecialchars($k['allowed_topic']); ?></code></td>
                                <td><?php echo !empty($k['allow_any_topic']) ? 'Wildcard' : 'Pinned'; ?></td>
                                <td><?php echo $k['is_enabled'] ? 'Active' : 'Revoked'; ?></td>
                                <td><?php echo $k['last_used_at'] ? htmlspecialchars($k['last_used_at']) : '-'; ?></td>
                                <td><?php echo htmlspecialchars($k['created_at']); ?></td>
                                <td>
                                    <button type="button" class="btn btn-sm btn-outline-danger" data-bs-toggle="modal" data-bs-target="#deleteKeyModal-<?php echo (int)$k['id']; ?>">
                                        Delete
                                    </button>
                                </td>
                            </tr>
                            <div class="modal fade" id="deleteKeyModal-<?php echo (int)$k['id']; ?>" tabindex="-1" aria-hidden="true">
                                <div class="modal-dialog">
                                    <div class="modal-content">
                                        <div class="modal-header">
                                            <h5 class="modal-title">Delete API Key</h5>
                                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                                        </div>
                                        <div class="modal-body">
                                            Are you sure you want to delete this API key for <code><?php echo htmlspecialchars($k['allowed_topic']); ?></code>?
                                        </div>
                                        <div class="modal-footer">
                                            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                                            <form method="POST" class="d-inline">
                                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
                                                <input type="hidden" name="delete_api_key" value="1">
                                                <input type="hidden" name="key_id" value="<?php echo (int)$k['id']; ?>">
                                                <button type="submit" class="btn btn-danger">Delete</button>
                                            </form>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
</div>

<div class="card shadow-sm mb-4">
    <div class="card-body">
        <h2 class="h5 mb-3">Create API Key</h2>
        <?php if ($error): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <?php if (!$created): ?>
            <div class="alert alert-info">
                You will only see the API key once. Save it immediately after creation.
            </div>
        <?php endif; ?>
        <?php if ($created): ?>
            <div class="alert alert-info">
                <p class="mb-2"><strong>API Key created. Save it now - you will not be able to view it again.</strong></p>
                <p class="mb-1">Allowed Topic (relative): <code><?php echo htmlspecialchars($createdRelativeTopic); ?></code></p>
                <p class="mb-1">Allowed Topic (full): <code><?php echo htmlspecialchars($created['allowedTopic']); ?></code></p>
                <p class="mb-1">Key Type: <strong><?php echo !empty($created['allowAnyTopic']) ? 'Wildcard' : 'Pinned'; ?></strong></p>
                <p class="mb-1">API Key: <code><?php echo htmlspecialchars($created['key']); ?></code></p>
                <p class="mb-0">Key ID: <?php echo htmlspecialchars($created['id']); ?></p>
            </div>
        <?php endif; ?>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($auth->getCsrfToken()); ?>">
            <input type="hidden" name="create_api_key" value="1">
            <div class="mb-3">
                <label for="topic" class="form-label">Allowed Topic</label>
                <input type="text" name="topic" id="topic" required placeholder="e.g., devices/your_device/data" class="form-control">
                <div class="form-text">Relative to <code><?php echo htmlspecialchars($user['username']); ?>/</code></div>
            </div>
            <div class="form-check mb-3">
                <input class="form-check-input" type="checkbox" id="allow_any_topic" name="allow_any_topic" value="1">
                <label class="form-check-label" for="allow_any_topic">
                    Allow any topic under <code><?php echo htmlspecialchars($user['username']); ?>/</code>
                </label>
                <div class="form-text">Choose one: a single topic above or any topic here.</div>
                <div class="form-text">
                    For example:
                    <ul class="mb-0">
                        <li><code><?php echo htmlspecialchars($user['username']); ?>/status</code></li>
                        <li><code><?php echo htmlspecialchars($user['username']); ?>/devices/device1</code></li>
                        <li><code><?php echo htmlspecialchars($user['username']); ?>/alerts/high</code></li>
                    </ul>
                </div>
            </div>
            <button type="submit" class="btn btn-primary">Create API Key</button>
        </form>
        <script>
            (function () {
                var checkbox = document.getElementById('allow_any_topic');
                var topicInput = document.getElementById('topic');

                if (!checkbox || !topicInput) {
                    return;
                }

                function syncTopicInput() {
                    if (checkbox.checked) {
                        topicInput.value = '';
                        topicInput.disabled = true;
                        topicInput.required = false;
                        topicInput.classList.add('bg-light');
                    } else {
                        topicInput.disabled = false;
                        topicInput.required = true;
                        topicInput.classList.remove('bg-light');
                    }
                }

                checkbox.addEventListener('change', syncTopicInput);
                syncTopicInput();
            })();
        </script>
    </div>
</div>

<div class="card shadow-sm">
    <div class="card-body">
        <h2 class="h5 mb-3">How API Keys Work</h2>
        <p class="text-muted">API keys let you publish to MQTT over HTTP. If you allow any topic, your request must include a <code>topic</code>. If you specify a <code>topic</code> when creating the API key, the API ignores the <code>topic</code> in the request and always uses the one you pinned when creating it.</p>
        <h3 class="h6">Example curl command</h3>
        <pre class="bg-light p-3 rounded"><code>curl -X POST <?php echo htmlspecialchars(APP_URL); ?>/public/api/publish.php \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "topic": "devices/device1",
    "message": "Hello from the API"
  }'
</code></pre>
    </div>
</div>

<?php require_once __DIR__ . '/../../includes/footer.php'; ?>
