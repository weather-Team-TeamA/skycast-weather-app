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

require_once '../Auth/db.php';

$data = json_decode(file_get_contents("php://input"));

if (!isset($data->id) || !isset($data->user_id)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing required fields']);
    exit;
}

$id = (int)$data->id;
$userId = (int)$data->user_id;

try {
    $stmt = $pdo->prepare("DELETE FROM saved_locations WHERE id = ? AND user_id = ?");
    $stmt->execute([$id, $userId]);

    if ($stmt->rowCount() === 0) {
        http_response_code(404);
        echo json_encode(['error' => 'Location not found']);
        exit;
    }

    echo json_encode(['message' => 'Location deleted']);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}
?>
