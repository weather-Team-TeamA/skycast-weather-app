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
    if (isIpThrottled($pdo, $ip, 'send_otp', 60, 3600)) {
        http_response_code(429);
        echo json_encode(['error' => 'Too many requests. Please try again later.']);
        logOtpEvent($pdo, $email, $ip, 'send_otp', false, 'ip_throttled');
        exit;
    }

    // Per-email limits: 15 per hour, 10 per day.
    $hourLimit = 15;
    $dayLimit = 10;
    $hourWindow = 3600;
    $dayWindow = 86400;

    // Daily limit check
    $since = date('Y-m-d H:i:s', time() - $dayWindow);
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) AS cnt, MIN(created_at) AS first_at FROM otp_audit_log
         WHERE email = ? AND action = ? AND created_at >= ?'
    );
    $stmt->execute([$email, 'send_otp', $since]);
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
        logOtpEvent($pdo, $email, $ip, 'send_otp', false, 'email_daily_throttled');
        exit;
    }

    // Hourly limit check
    $since = date('Y-m-d H:i:s', time() - $hourWindow);
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) AS cnt, MIN(created_at) AS first_at FROM otp_audit_log
         WHERE email = ? AND action = ? AND created_at >= ?'
    );
    $stmt->execute([$email, 'send_otp', $since]);
    $row = $stmt->fetch();
    if ((int)($row['cnt'] ?? 0) >= $hourLimit) {
        $remaining = 0;
        if (!empty($row['first_at'])) {
            $first = strtotime($row['first_at']);
            if ($first !== false) {
                $remaining = $hourWindow - (time() - $first);
                if ($remaining < 0) $remaining = 0;
            }
        }
        http_response_code(429);
        echo json_encode([
            'error' => 'Too many requests. Please try again later.',
            'remaining_seconds' => $remaining
        ]);
        logOtpEvent($pdo, $email, $ip, 'send_otp', false, 'email_hourly_throttled');
        exit;
    }

    // Enforce email domain allowlist (production).
    if (ALLOWLIST_ENABLED) {
        $parts = explode('@', $email);
        $domain = isset($parts[1]) ? strtolower($parts[1]) : '';
        if (empty($domain) || !in_array($domain, ALLOWED_EMAIL_DOMAINS, true)) {
            http_response_code(403);
            echo json_encode(['error' => 'Email domain not allowed']);
            logOtpEvent($pdo, $email, $ip, 'send_otp', false, 'domain_blocked');
            exit;
        }
    }

    // Look up user (do not reveal if user exists).
    $stmt = $pdo->prepare('SELECT id, name FROM users WHERE email = ? LIMIT 1');
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if ($user) {
        // Check lockout for this email
        $stmt = $pdo->prepare(
            'SELECT locked_until FROM password_otps WHERE email = ? ORDER BY id DESC LIMIT 1'
        );
        $stmt->execute([$email]);
        $lockRow = $stmt->fetch();
        if (!empty($lockRow['locked_until']) && strtotime($lockRow['locked_until']) > time()) {
            $remaining = remainingSeconds($lockRow['locked_until']);
            http_response_code(429);
            echo json_encode([
                'error' => 'Too many attempts. Please request a new code later.',
                'remaining_seconds' => $remaining
            ]);
            logOtpEvent($pdo, $email, $ip, 'send_otp', false, 'locked');
            exit;
        }

        // Rate limit: allow resend every 30 seconds.
        $stmt = $pdo->prepare(
            'SELECT last_sent_at FROM password_otps WHERE email = ? AND used_at IS NULL ORDER BY id DESC LIMIT 1'
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
                logOtpEvent($pdo, $email, $ip, 'send_otp', false, 'cooldown');
                exit;
            }
        }

        // Generate OTP
        $otp = strval(random_int(100000, 999999));
        $otpHash = password_hash($otp, PASSWORD_DEFAULT);
        // Remove old OTPs for this email
        $stmt = $pdo->prepare('DELETE FROM password_otps WHERE email = ?');
        $stmt->execute([$email]);

        // Insert new OTP record
        $stmt = $pdo->prepare(
            'INSERT INTO password_otps (user_id, email, otp_hash, expires_at, created_at, last_sent_at, attempts)
             VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 10 MINUTE), NOW(), NOW(), 0)'
        );
        $stmt->execute([$user['id'], $email, $otpHash]);

        // Send email
        $name = $user['name'] ?? 'SkyCast User';
        try {
            sendPasswordResetOtpEmail($email, $name, $otp);
        } catch (Exception $e) {
            $stmt = $pdo->prepare('DELETE FROM password_otps WHERE email = ?');
            $stmt->execute([$email]);
            logOtpEvent($pdo, $email, $ip, 'send_otp', false, 'email_failed');
            throw $e;
        }
    }

    // Always return generic success
    echo json_encode([
        'message' => 'If an account with that email exists, a verification code has been sent.'
    ]);
    logOtpEvent($pdo, $email, $ip, 'send_otp', true, 'sent');
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Server error: ' . $e->getMessage()]);
    logOtpEvent($pdo, $email, $ip, 'send_otp', false, 'server_error');
}
?>
