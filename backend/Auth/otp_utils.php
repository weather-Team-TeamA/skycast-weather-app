<?php
function getClientIp(): string {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($parts[0]);
    }
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function logOtpEvent(PDO $pdo, ?string $email, string $ip, string $action, bool $success, string $message = ''): void {
    $stmt = $pdo->prepare(
        'INSERT INTO otp_audit_log (email, ip_address, action, success, message, created_at)
         VALUES (?, ?, ?, ?, ?, NOW())'
    );
    $stmt->execute([$email, $ip, $action, $success ? 1 : 0, $message]);
}

function isIpThrottled(PDO $pdo, string $ip, string $action, int $limit, int $windowSeconds): bool {
    $since = date('Y-m-d H:i:s', time() - $windowSeconds);
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) AS cnt FROM otp_audit_log
         WHERE ip_address = ? AND action = ? AND created_at >= ?'
    );
    $stmt->execute([$ip, $action, $since]);
    $row = $stmt->fetch();
    return ((int)($row['cnt'] ?? 0)) >= $limit;
}

function remainingSeconds(string $lockedUntil): int {
    $ts = strtotime($lockedUntil);
    if ($ts === false) {
        return 0;
    }
    $remaining = $ts - time();
    return $remaining > 0 ? $remaining : 0;
}
?>
