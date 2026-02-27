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

// Deprecated: use send_otp.php instead.
http_response_code(410);
echo json_encode([
    'error' => 'Endpoint deprecated. Use send_otp.php'
]);
?>
