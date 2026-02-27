<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method Not Allowed']);
    exit;
}

require_once 'db.php';

$data = json_decode(file_get_contents("php://input"));

if (!isset($data->user_id) || !isset($data->old_password) || !isset($data->new_password)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing user_id, old_password or new_password']);
    exit;
}

$user_id     = (int) $data->user_id;
$old_password = $data->old_password;
$new_password = $data->new_password;

if (strlen($new_password) < 6) {
    http_response_code(400);
    echo json_encode(['error' => 'New password must be at least 6 characters']);
    exit;
}

try {
    // Fetch the current password hash for the user
    $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = ?");
    $stmt->execute([$user_id]);
    $user = $stmt->fetch();

    if (!$user) {
        http_response_code(404);
        echo json_encode(['error' => 'User not found']);
        exit;
    }

    // Verify old password
    if (!password_verify($old_password, $user['password_hash'])) {
        http_response_code(401);
        echo json_encode(['error' => 'Old password is incorrect']);
        exit;
    }

    // Hash the new password and update
    $new_hash = password_hash($new_password, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
    $stmt->execute([$new_hash, $user_id]);

    http_response_code(200);
    echo json_encode(['message' => 'Password changed successfully']);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}
?>
