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
require_once 'mailer.php';
require_once 'otp_utils.php';

$data = json_decode(file_get_contents('php://input'));

if (!isset($data->email)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing email']);
    exit;
}

$email = trim(strtolower($data->email));
$ip = getClientIp();

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid email']);
    exit;
}

try {
    if (isIpThrottled($pdo, $ip, 'signup_send_otp', 60, 3600)) {
        http_response_code(429);
        echo json_encode(['error' => 'Too many requests. Please try again later.']);
        logOtpEvent($pdo, $email, $ip, 'signup_send_otp', false, 'ip_throttled');
        exit;
    }

    // Per-email daily limit: 10 per day.
    $dayLimit = 10;
    $dayWindow = 86400;

    $since = date('Y-m-d H:i:s', time() - $dayWindow);
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) AS cnt, MIN(created_at) AS first_at FROM otp_audit_log
         WHERE email = ? AND action = ? AND created_at >= ?'
    );
    $stmt->execute([$email, 'signup_send_otp', $since]);
    $row = $stmt->fetch();
    if ((int)($row['cnt'] ?? 0) >= $dayLimit) {
        $remaining = 0;
        if (!empty($row['first_at'])) {
            $first = strtotime($row['first_at']);
            if ($first !== false) {
                $remaining = $dayWindow - (time() - $first);
                if ($remaining < 0) $remaining = 0;
            }
        }
        http_response_code(429);
        echo json_encode([
            'error' => 'Daily limit reached. Please try again later.',
            'remaining_seconds' => $remaining
        ]);
        logOtpEvent($pdo, $email, $ip, 'signup_send_otp', false, 'email_daily_throttled');
        exit;
    }

    // Reject if email already exists
    $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        http_response_code(409);
        echo json_encode(['error' => 'Email already exists']);
        logOtpEvent($pdo, $email, $ip, 'signup_send_otp', false, 'email_exists');
        exit;
    }

    // Rate limit: allow resend every 30 seconds.
    $stmt = $pdo->prepare(
        'SELECT last_sent_at FROM signup_otps WHERE email = ? AND used_at IS NULL ORDER BY id DESC LIMIT 1'
    );
    $stmt->execute([$email]);
    $row = $stmt->fetch();
    if ($row && !empty($row['last_sent_at'])) {
        $lastSent = strtotime($row['last_sent_at']);
        if ($lastSent !== false && (time() - $lastSent) < 30) {
            $remaining = 30 - (time() - $lastSent);
            if ($remaining < 0) $remaining = 0;
            http_response_code(429);
            echo json_encode([
                'error' => 'Please wait before requesting another code.',
                'remaining_seconds' => $remaining
            ]);
            logOtpEvent($pdo, $email, $ip, 'signup_send_otp', false, 'cooldown');
            exit;
        }
    }

    // Generate OTP
    $otp = strval(random_int(100000, 999999));
    $otpHash = password_hash($otp, PASSWORD_DEFAULT);
    // Remove old OTPs
    $stmt = $pdo->prepare('DELETE FROM signup_otps WHERE email = ?');
    $stmt->execute([$email]);

    // Insert new OTP
    $stmt = $pdo->prepare(
        'INSERT INTO signup_otps (email, otp_hash, expires_at, created_at, last_sent_at, attempts)
         VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE), NOW(), NOW(), 0)'
    );
    $stmt->execute([$email, $otpHash]);

    // Send email
    try {
        sendSignupOtpEmail($email, 'SkyCast User', $otp);
    } catch (Exception $e) {
        $stmt = $pdo->prepare('DELETE FROM signup_otps WHERE email = ?');
        $stmt->execute([$email]);
        logOtpEvent($pdo, $email, $ip, 'signup_send_otp', false, 'email_failed');
        throw $e;
    }

    echo json_encode(['message' => 'Verification code sent']);
    logOtpEvent($pdo, $email, $ip, 'signup_send_otp', true, 'sent');
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Server error: ' . $e->getMessage()]);
    logOtpEvent($pdo, $email, $ip, 'signup_send_otp', false, 'server_error');
}
?>
