<?php
require_once __DIR__ . '/mailer_config.php';

// Prefer Composer autoload if available.
$autoload = __DIR__ . '/../vendor/autoload.php';
if (file_exists($autoload)) {
    require_once $autoload;
}

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

function sendOtpEmail(string $toEmail, string $toName, string $otp, string $purpose): void {
    if (!class_exists(PHPMailer::class)) {
        throw new Exception('PHPMailer not installed. Run: composer require phpmailer/phpmailer');
    }

    $subject = 'SkyCast - Verification Code';
    $headline = 'Use the verification code below to continue.';
    if ($purpose === 'reset') {
        $subject = 'SkyCast - Password Reset Code';
        $headline = 'Use the verification code below to reset your SkyCast password.';
    } elseif ($purpose === 'signup') {
        $subject = 'SkyCast - Email Verification Code';
        $headline = 'Use the verification code below to verify your SkyCast email.';
    }

    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->Host = SMTP_HOST;
    $mail->SMTPAuth = true;
    $mail->Username = SMTP_USERNAME;
    $mail->Password = SMTP_PASSWORD;
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port = SMTP_PORT;

    $mail->setFrom(SMTP_FROM_EMAIL, SMTP_FROM_NAME);
    $mail->addAddress($toEmail, $toName);
    $mail->isHTML(true);
    $mail->Subject = $subject;

    $safeName = htmlspecialchars($toName ?: 'SkyCast User', ENT_QUOTES, 'UTF-8');
    $safeOtp = htmlspecialchars($otp, ENT_QUOTES, 'UTF-8');
    $safeHeadline = htmlspecialchars($headline, ENT_QUOTES, 'UTF-8');

    $mail->Body = "
    <div style=\"font-family: Arial, sans-serif; background: #0A192F; color: #fff; padding: 24px;\">
      <div style=\"max-width: 520px; margin: 0 auto; background: #101f3a; padding: 24px; border-radius: 12px;\">
        <h2 style=\"margin: 0 0 8px; color: #FFBF00;\">SkyCast</h2>
        <p style=\"margin: 0 0 16px;\">Hi {$safeName},</p>
        <p style=\"margin: 0 0 12px;\">{$safeHeadline}</p>
        <div style=\"font-size: 28px; font-weight: bold; letter-spacing: 6px; padding: 12px 16px; background: #0A192F; border-radius: 8px; text-align: center; color: #FFBF00;\">
          {$safeOtp}
        </div>
        <p style=\"margin: 16px 0 0; font-size: 13px; color: #cbd5e1;\">This code expires in 10 minutes and can only be used once.</p>
        <p style=\"margin: 8px 0 0; font-size: 12px; color: #94a3b8;\">If you did not request this, you can ignore this email.</p>
      </div>
    </div>";

    $mail->AltBody = "SkyCast verification code: {$otp}. This code expires in 10 minutes.";

    $mail->send();
}

function sendPasswordResetOtpEmail(string $toEmail, string $toName, string $otp): void {
    sendOtpEmail($toEmail, $toName, $otp, 'reset');
}

function sendSignupOtpEmail(string $toEmail, string $toName, string $otp): void {
    sendOtpEmail($toEmail, $toName, $otp, 'signup');
}
?>
