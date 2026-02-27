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

if (!isset($data->user_id) || !isset($data->city_name) || !isset($data->latitude) || !isset($data->longitude)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing required fields']);
    exit;
}

try {
    // Check if location already exists for user
    $stmt = $pdo->prepare("SELECT id FROM saved_locations WHERE user_id = ? AND city_name = ?");
    $stmt->execute([$data->user_id, $data->city_name]);
    if ($stmt->fetch()) {
        http_response_code(409); // Conflict
        echo json_encode(['error' => 'Location already saved']);
        exit;
    }

    $stmt = $pdo->prepare("INSERT INTO saved_locations (user_id, city_name, latitude, longitude) VALUES (?, ?, ?, ?)");
    $stmt->execute([$data->user_id, $data->city_name, $data->latitude, $data->longitude]);

    $id = (int)$pdo->lastInsertId();
    http_response_code(201);
    echo json_encode([
        'message' => 'Location saved successfully',
        'id' => $id
    ]);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}
?>
