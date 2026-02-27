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

if (!isset($data->email) || !isset($data->password)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing email or password']);
    exit;
}

$email = $data->email;
$password = $data->password;

try {
    $stmt = $pdo->prepare("SELECT id, name, password_hash FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password_hash'])) {
        http_response_code(200);
        echo json_encode([
            'message' => 'Login successful',
            'user' => [
                'id' => $user['id'],
                'name' => $user['name'],
                'email' => $email
            ]
        ]);
    } else {
        http_response_code(401);
        if (!$user) {
            echo json_encode(['error' => 'Email not registered']);
        } else {
            echo json_encode(['error' => 'Incorrect password']);
        }
    }
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}
?>
