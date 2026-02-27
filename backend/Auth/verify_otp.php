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

if (!isset($data->email) || !isset($data->otp)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing email or otp']);
    exit;
}

$email = trim(strtolower($data->email));
$otp = trim($data->otp);
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

try {
    if (isIpThrottled($pdo, $ip, 'verify_otp', 10, 600)) {
        http_response_code(429);
        echo json_encode(['error' => 'Too many requests. Please try again later.']);
        logOtpEvent($pdo, $email, $ip, 'verify_otp', false, 'ip_throttled');
        exit;
    }

    $stmt = $pdo->prepare(
        'SELECT id, otp_hash, attempts, expires_at, used_at, locked_until FROM password_otps
         WHERE email = ? AND used_at IS NULL ORDER BY id DESC LIMIT 1'
    );
    $stmt->execute([$email]);
    $row = $stmt->fetch();

    if (!$row) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid or expired OTP']);
        logOtpEvent($pdo, $email, $ip, 'verify_otp', false, 'no_record');
        exit;
    }

    if (!empty($row['locked_until']) && strtotime($row['locked_until']) > time()) {
        $remaining = remainingSeconds($row['locked_until']);
        http_response_code(429);
        echo json_encode([
            'error' => 'Too many attempts. Please request a new code in 15 minutes.',
            'remaining_seconds' => $remaining
        ]);
        logOtpEvent($pdo, $email, $ip, 'verify_otp', false, 'locked');
        exit;
    }

    if (strtotime($row['expires_at']) <= time()) {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid or expired OTP']);
        logOtpEvent($pdo, $email, $ip, 'verify_otp', false, 'expired');
        exit;
    }

    if (!password_verify($otp, $row['otp_hash'])) {
        $attempts = (int)($row['attempts'] ?? 0) + 1;
        if ($attempts >= 5) {
            $stmt = $pdo->prepare(
                'UPDATE password_otps SET attempts = ?, locked_until = DATE_ADD(NOW(), INTERVAL 15 MINUTE), used_at = NOW()
                 WHERE id = ?'
            );
            $stmt->execute([$attempts, $row['id']]);
            $remaining = 15 * 60;
            http_response_code(429);
            echo json_encode([
                'error' => 'Too many attempts. Please request a new code in 15 minutes.',
                'remaining_seconds' => $remaining
            ]);
            logOtpEvent($pdo, $email, $ip, 'verify_otp', false, 'locked');
            exit;
        }

        $stmt = $pdo->prepare('UPDATE password_otps SET attempts = ? WHERE id = ?');
        $stmt->execute([$attempts, $row['id']]);

        http_response_code(400);
        echo json_encode(['error' => 'Invalid or expired OTP']);
        logOtpEvent($pdo, $email, $ip, 'verify_otp', false, 'invalid');
        exit;
    }

    $stmt = $pdo->prepare('UPDATE password_otps SET verified_at = NOW() WHERE id = ?');
    $stmt->execute([$row['id']]);

    echo json_encode(['message' => 'OTP verified']);
    logOtpEvent($pdo, $email, $ip, 'verify_otp', true, 'verified');
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database error: ' . $e->getMessage()]);
    logOtpEvent($pdo, $email, $ip, 'verify_otp', false, 'server_error');
}
?>
