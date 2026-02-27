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

if (!isset($data->name) || !isset($data->email) || !isset($data->password)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing required fields']);
    exit;
}

$name = $data->name;
$email = strtolower(trim($data->email));
$password = $data->password;

// Simple validation
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid email address']);
    exit;
}

$domain = substr(strrchr($email, "@"), 1);
if ($domain === false || $domain === '') {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid email address']);
    exit;
}

if (function_exists('checkdnsrr')) {
    $hasMx = checkdnsrr($domain, 'MX');
    $hasA = checkdnsrr($domain, 'A');
    if (!$hasMx && !$hasA) {
        http_response_code(400);
        echo json_encode(['error' => 'Email domain not valid']);
        exit;
    }
}

if (strlen($password) < 6) {
    http_response_code(400);
    echo json_encode(['error' => 'Password must be at least 6 characters']);
    exit;
}

$password_hash = password_hash($password, PASSWORD_DEFAULT);

try {
    // Require verified OTP for signup
    $stmt = $pdo->prepare(
        'SELECT id FROM signup_otps
         WHERE email = ? AND verified_at IS NOT NULL AND used_at IS NULL AND expires_at > NOW()
         ORDER BY id DESC LIMIT 1'
    );
    $stmt->execute([$email]);
    $otpRow = $stmt->fetch();
    if (!$otpRow) {
        http_response_code(400);
        echo json_encode(['error' => 'Email not verified']);
        exit;
    }

    // Check if email exists
    $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        http_response_code(409);
        echo json_encode(['error' => 'Email already exists']);
        exit;
    }

    // Insert user
    $stmt = $pdo->prepare("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)");
    $stmt->execute([$name, $email, $password_hash]);

    // Mark OTP used
    $stmt = $pdo->prepare("UPDATE signup_otps SET used_at = NOW() WHERE id = ?");
    $stmt->execute([$otpRow['id']]);

    http_response_code(201);
    echo json_encode(['message' => 'User registered successfully']);

} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
}
?>
