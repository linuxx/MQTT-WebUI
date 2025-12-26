<?php
/**
 * API Gateway: Publish to MQTT via HTTP using API Key
 *
 * Endpoint: POST /public/api/publish.php
 * Headers: X-API-Key: <key>
 * Content-Type: application/json
 * Body: { "topic": "string", "message": "string" }
 */

require_once __DIR__ . '/../../includes/bootstrap.php';

// We don't require user session for API key access

$apiKeyHeader = $_SERVER['HTTP_X_API_KEY'] ?? '';
if (empty($apiKeyHeader)) {
    http_response_code(401);
    echo json_encode(['error' => 'API key missing']);
    exit;
}

$rawBody = file_get_contents('php://input');
$data = json_decode($rawBody, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid JSON']);
    exit;
}

$topic = isset($data['topic']) ? trim($data['topic']) : '';
$message = isset($data['message']) ? trim($data['message']) : '';

if ($message === '') {
    http_response_code(400);
    echo json_encode(['error' => 'Message is required']);
    exit;
}

// Validate API key
$apiKeyManager = new ApiKeyManager();
$keyData = $apiKeyManager->validateApiKey($apiKeyHeader);
if (!$keyData) {
    http_response_code(403);
    echo json_encode(['error' => 'Invalid or revoked API key']);
    exit;
}

// Ensure allowed topic exists and matches
if (!empty($keyData['allow_any_topic'])) {
    if ($topic === '') {
        http_response_code(400);
        echo json_encode(['error' => 'Topic is required for this API key']);
        exit;
    }

    $topic = ltrim($topic, '/');
    if (strpos($topic, $keyData['username'] . '/') !== 0) {
        $topic = $keyData['username'] . '/' . $topic;
    }
} else {
    $topic = $keyData['allowed_topic'];
}

// Very basic topic validation to prevent topic injection
$topicErrors = SecurityUtil::validateMqttTopic($topic);
if (!empty($topicErrors)) {
    http_response_code(403);
    echo json_encode(['error' => 'Configured topic is invalid']);
    exit;
}

// Sanitize payload
$payload = [
    'message' => htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
    'timestamp' => time(),
];

// Publish to MQTT using php mqtt client (pecl or external). We'll use a lightweight publish via shell mosquitto_pub if available.
// Note: In production, replace with a persistent server-side MQTT client library.

$payloadJson = json_encode($payload);
$publishSuccess = false;

// Prefer ext-sockets/mqtt library if available
if (class_exists('Mosquitto\Client')) {
    try {
        $client = new Mosquitto\Client();
        $client->setCredentials(MQTT_USER, MQTT_PASS);
        $client->connect(MQTT_HOST, MQTT_PORT, 5);
        $client->publish($topic, $payloadJson, 1);
        $client->loop(10);
        $client->disconnect();
        $publishSuccess = true;
    } catch (Exception $e) {
        error_log('MQTT publish failed: ' . $e->getMessage());
        $publishSuccess = false;
    }
} else {
    // Fallback to mosquitto_pub command if available on the system
    $cmd = sprintf(
        'mosquitto_pub -h %s -p %d -u %s -P %s -t %s -m %s',
        escapeshellarg(MQTT_HOST),
        (int)MQTT_PORT,
        escapeshellarg(MQTT_USER),
        escapeshellarg(MQTT_PASS),
        escapeshellarg($topic),
        escapeshellarg($payloadJson)
    );

    exec($cmd . ' 2>&1', $output, $returnVar);
    if ($returnVar === 0) {
        $publishSuccess = true;
    } else {
        error_log('mosquitto_pub failed: ' . implode('\n', $output));
        $publishSuccess = false;
    }
}

if (!$publishSuccess) {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to publish to MQTT']);
    exit;
}

// Update last used timestamp
$apiKeyManager->updateLastUsed($keyData['id']);

// Audit log (optional)
$auditEnabled = defined('API_AUDIT_LOG_ENABLED') ? API_AUDIT_LOG_ENABLED : true;
if ($auditEnabled) {
    $audit = new AuditLogger();
    $audit->log('api_publish', 'api_key', $keyData['id'], "API key used to publish to topic {$topic}");
}

http_response_code(200);
echo json_encode(['status' => 'published']);
exit;

