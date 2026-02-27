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
require_once 'otp_utils.php';

$data = json_decode(file_get_contents('php://input'));

if (!isset($data->email) || !isset($data->otp) || !isset($data->new_password)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing email, otp, or new password']);
    exit;
}

$email = trim(strtolower($data->email));
$otp = trim($data->otp);
$newPassword = $data->new_password;
$ip = getClientIp();

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid email']);
    exit;
}

if (!preg_match('/^\d{6}$/', $otp)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid OTP format']);
    exit;
}

if (strlen($newPassword) < 6) {
    http_response_code(400);
    echo json_encode(['error' => 'Password must be at least 6 characters']);
    exit;
}

try {
    $stmt = $pdo->prepare(
        'SELECT id, otp_hash, expires_at, verified_at, used_at, locked_until FROM password_otps
         WHERE email = ? AND used_at IS NULL ORDER BY id DESC LIMIT 1'
    );
    $stmt->execute([$email]);
    $row = $stmt->fetch();

    if (!$row) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid or expired OTP']);
        logOtpEvent($pdo, $email, $ip, 'reset_password', false, 'no_record');
        exit;
    }

    if (!empty($row['locked_until']) && strtotime($row['locked_until']) > time()) {
        $remaining = remainingSeconds($row['locked_until']);
        http_response_code(429);
        echo json_encode([
            'error' => 'Too many attempts. Please request a new code later.',
            'remaining_seconds' => $remaining
        ]);
        logOtpEvent($pdo, $email, $ip, 'reset_password', false, 'locked');
        exit;
    }

    if (strtotime($row['expires_at']) <= time()) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid or expired OTP']);
        logOtpEvent($pdo, $email, $ip, 'reset_password', false, 'expired');
        exit;
    }

    if (empty($row['verified_at'])) {
        http_response_code(400);
        echo json_encode(['error' => 'OTP not verified']);
        logOtpEvent($pdo, $email, $ip, 'reset_password', false, 'not_verified');
        exit;
    }

    if (!password_verify($otp, $row['otp_hash'])) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid or expired OTP']);
        logOtpEvent($pdo, $email, $ip, 'reset_password', false, 'invalid');
        exit;
    }

    $pdo->beginTransaction();

    $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare('UPDATE users SET password_hash = ? WHERE email = ?');
    $stmt->execute([$passwordHash, $email]);

    $stmt = $pdo->prepare('UPDATE password_otps SET used_at = NOW() WHERE id = ?');
    $stmt->execute([$row['id']]);

    $pdo->commit();

    echo json_encode(['message' => 'Password reset successfully']);
    logOtpEvent($pdo, $email, $ip, 'reset_password', true, 'reset');
} catch (PDOException $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    logOtpEvent($pdo, $email, $ip, 'reset_password', false, 'server_error');
}
?>
