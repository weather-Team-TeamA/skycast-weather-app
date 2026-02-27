<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    echo json_encode(['error' => 'Method Not Allowed']);
    exit;
}

require_once '../Auth/db.php';

if (!isset($_GET['user_id'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing user_id']);
    exit;
}

$user_id = $_GET['user_id'];

try {
    $stmt = $pdo->prepare("SELECT * FROM saved_locations WHERE user_id = ? ORDER BY created_at DESC");
    $stmt->execute([$user_id]);
    $locations = $stmt->fetchAll();

    http_response_code(200);
    echo json_encode($locations);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}
?>
