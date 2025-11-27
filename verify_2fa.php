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

$error = '';

// Kiểm tra có phiên chờ 2FA hay không
if (!isset($_SESSION['pending_2fa_user_id']) || !isset($_SESSION['pending_2fa_username'])) {
    header('Location: index.php');
    exit();
}

// Hết hạn
if (isset($_SESSION['pending_2fa_expires']) && time() > (int)$_SESSION['pending_2fa_expires']) {
    session_unset();
    session_destroy();
    session_start();
    $error = 'Phiên 2FA đã hết hạn. Vui lòng đăng nhập lại.';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $otp = isset($_POST['otp']) ? trim($_POST['otp']) : '';
    $username = $_SESSION['pending_2fa_username'];

    if ($otp === '') {
        $error = 'Vui lòng nhập mã OTP!';
    } else {
        // Lấy OTP mới nhất cho user bằng prepared statement
        if ($stmt = $config->prepare("SELECT otp_code FROM emails WHERE username = ? ORDER BY created_at DESC, id DESC LIMIT 1")) {
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $stmt->bind_result($otp_code);
            if ($stmt->fetch()) {
                if (hash_equals((string)$otp_code, (string)$otp)) {
                    // Xác minh thành công -> thiết lập đăng nhập đầy đủ
                    session_regenerate_id(true);
                    $_SESSION['username'] = $_SESSION['pending_2fa_username'];
                    $_SESSION['role'] = $_SESSION['pending_2fa_role'] ?? 'user';

                    // Xóa trạng thái 2FA tạm
                    unset($_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_username'], $_SESSION['pending_2fa_role'], $_SESSION['pending_2fa_expires']);

                    header('Location: my_account.php');
                    exit();
                } else {
                    $error = 'Mã OTP không đúng!';
                }
            } else {
                $error = 'Không tìm thấy OTP. Hãy thử đăng nhập lại.';
            }
            $stmt->close();
        } else {
            $error = 'Lỗi hệ thống.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Xác minh 2FA</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="galaxy-bg">
        <div class="circle blue1"></div>
        <div class="circle blue2"></div>
        <div class="circle orange1"></div>
        <div class="circle orange2"></div>
    </div>
    <div class="register-glass" style="max-width:480px;">
        <h2 style="color:#fff;">Nhập mã xác minh 2FA</h2>
        <form method="post" action="verify_2fa.php" autocomplete="off">
            <div class="form-group">
                <span class="input-icon"><i class="fa fa-key"></i></span>
                <input type="text" name="otp" placeholder="Mã OTP" required>
            </div>
            <button type="submit" class="btn">Xác minh</button>
            <a class="btn" style="margin-left:10px; width:auto; padding:5px 16px; display:inline-block;" href="client_email.php?username=<?php echo urlencode($_SESSION['pending_2fa_username'] ?? ''); ?>">Email Client</a>
        </form>
        <?php if ($error): ?>
            <div class="alert alert-danger" style="margin-top:15px;">&nbsp;<?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
    </div>
</body>
</html>


