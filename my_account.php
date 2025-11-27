<?php
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://code.jquery.com https://cdnjs.cloudflare.com 'unsafe-inline'; style-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; font-src 'self' https://cdnjs.cloudflare.com data:; img-src 'self' data:;");
header('X-XSS-Protection: 1; mode=block');
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');

ini_set('session.cookie_samesite', 'lax');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_httponly', '1');

session_start();
require_once 'config.php';

// BẮT BUỘC: phải đăng nhập và đã xác minh 2FA (không chấp nhận pending 2FA)
if (!isset($_SESSION['username']) || isset($_SESSION['pending_2fa_user_id'])) {
    header('Location: index.php');
    exit();
}

$username = $_SESSION['username'];
$role = isset($_SESSION['role']) ? $_SESSION['role'] : 'user';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Account</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="galaxy-bg">
        <div class="circle blue1"></div>
        <div class="circle blue2"></div>
        <div class="circle orange1"></div>
        <div class="circle orange2"></div>
    </div>
    <div class="home-glass" style="max-width:760px;">
        <h2 style="color:#fff; margin-top:0;">Xin chào, <?php echo htmlspecialchars($username, ENT_QUOTES, 'UTF-8'); ?></h2>
        <p>Vai trò: <strong><?php echo htmlspecialchars($role, ENT_QUOTES, 'UTF-8'); ?></strong></p>
        <div style="margin-top:15px;">
            <a class="btn" href="home.php" style="width:auto; padding:6px 16px;">Home</a>
            <a class="btn" href="index.php" style="width:auto; padding:6px 16px; margin-left:8px;">Logout</a>
        </div>
    </div>
</body>
</html>


