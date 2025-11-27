<?php
ini_set('session.cookie_samesite', 'lax');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_httponly', '1');

session_start();
require_once 'config.php';

// BẢN FIX: Quy trình đặt lại mật khẩu an toàn
// - Không lộ enumeration: luôn trả lời chung khi yêu cầu reset
// - Sinh token ngẫu nhiên, lưu server-side trong bảng password_resets với hạn 15 phút
// - Link email chứa token; khi mở form, kiểm tra token còn hạn
// - Khi POST đổi mật khẩu: kiểm tra token + CSRF + độ mạnh mật khẩu; không tin hidden username
// - Cập nhật mật khẩu bằng password_hash; xóa token sau khi dùng

$message = '';
$error = '';

function base_url() {
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $path = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
    return $scheme . '://' . $host . ($path ? $path : '');
}

// Tạo bảng password_resets nếu chưa có
$config->query(
    "CREATE TABLE IF NOT EXISTS password_resets (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        token VARCHAR(255) NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX (username),
        UNIQUE KEY unique_token (token)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
);

// CSRF token cho form đổi mật khẩu
if (empty($_SESSION['csrf_reset'])) {
    $_SESSION['csrf_reset'] = bin2hex(random_bytes(16));
}

// Bước 1: Yêu cầu đặt lại mật khẩu
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'request') {
    $username = isset($_POST['username']) ? trim($_POST['username']) : '';
    // Không lộ enumeration: luôn hiển thị cùng một thông báo
    $genericMsg = 'Nếu tài khoản tồn tại, chúng tôi đã gửi email đặt lại.';

    if ($username === '') {
        $error = 'Vui lòng nhập username';
    } else {
        // Kiểm tra user có tồn tại không (im lặng)
        $userExists = false;
        if ($stmt = $config->prepare('SELECT email FROM users WHERE username = ? LIMIT 1')) {
            $stmt->bind_param('s', $username);
            $stmt->execute();
            $res = $stmt->get_result();
            $user = $res ? $res->fetch_assoc() : null;
            $stmt->close();
            $userExists = (bool)$user;
        }

        // Dù có hay không, vẫn tạo token nếu user tồn tại; nếu không, bỏ qua nhưng vẫn trả lời chung
        if ($userExists) {
            $token = bin2hex(random_bytes(32));
            $expires = (new DateTime('+15 minutes'))->format('Y-m-d H:i:s');
            // Xóa token cũ của user (nếu có)
            if ($del = $config->prepare('DELETE FROM password_resets WHERE username = ?')) {
                $del->bind_param('s', $username);
                $del->execute();
                $del->close();
            }
            // Lưu token mới
            if ($ins = $config->prepare('INSERT INTO password_resets (username, token, expires_at) VALUES (?,?,?)')) {
                $ins->bind_param('sss', $username, $token, $expires);
                $ins->execute();
                $ins->close();
            }

            // Gửi email (ghi vào bảng emails)
            $emailAddr = $user['email'] ?? '';
            $resetLink = base_url() . '/forgot_password.php?temp-forgot-password-token=' . urlencode($token);
            if ($mail = $config->prepare('INSERT INTO emails (username, email, subject, body, otp_code) VALUES (?,?,?,?,?)')) {
                $subject = 'Password reset';
                $body = 'Click link to reset: ' . $resetLink;
                $otp = '';
                $mail->bind_param('sssss', $username, $emailAddr, $subject, $body, $otp);
                $mail->execute();
                $mail->close();
            }
        }

        $message = $genericMsg;
    }
}

// Kiểm tra token trên URL
$tokenOnUrl = isset($_GET['temp-forgot-password-token']) ? $_GET['temp-forgot-password-token'] : '';
$tokenValid = false;
$tokenUsername = '';
if ($tokenOnUrl !== '') {
    if ($stmt = $config->prepare('SELECT username, expires_at FROM password_resets WHERE token = ? LIMIT 1')) {
        $stmt->bind_param('s', $tokenOnUrl);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($row = $res->fetch_assoc()) {
            $tokenUsername = $row['username'];
            $tokenValid = (strtotime($row['expires_at']) > time());
        }
        $stmt->close();
    }
}

// Bước 3: Xác nhận đổi mật khẩu an toàn
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'reset') {
    $csrf = $_POST['csrf'] ?? '';
    $tokenFromUrl = $_GET['temp-forgot-password-token'] ?? '';
    $newPassword = $_POST['new_password'] ?? '';

    if (!hash_equals($_SESSION['csrf_reset'] ?? '', $csrf)) {
        $error = 'CSRF token không hợp lệ';
    } elseif ($tokenFromUrl === '') {
        $error = 'Thiếu token';
    } else {
        // Lấy user theo token và kiểm tra hạn
        $usernameForToken = '';
        $expiresAt = '';
        if ($stmt = $config->prepare('SELECT username, expires_at FROM password_resets WHERE token = ? LIMIT 1')) {
            $stmt->bind_param('s', $tokenFromUrl);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($row = $res->fetch_assoc()) {
                $usernameForToken = $row['username'];
                $expiresAt = $row['expires_at'];
            }
            $stmt->close();
        }

        if ($usernameForToken === '' || strtotime($expiresAt) <= time()) {
            $error = 'Link đặt lại không hợp lệ hoặc đã hết hạn';
        } elseif (strlen($newPassword) < 6) {
            $error = 'Mật khẩu phải có ít nhất 6 ký tự';
        } else {
            // Cập nhật mật khẩu đã hash
            $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);
            if ($upd = $config->prepare('UPDATE users SET password = ? WHERE username = ?')) {
                $upd->bind_param('ss', $passwordHash, $usernameForToken);
                $upd->execute();
                $upd->close();
            }
            // Xóa token sau khi dùng
            if ($del = $config->prepare('DELETE FROM password_resets WHERE token = ?')) {
                $del->bind_param('s', $tokenFromUrl);
                $del->execute();
                $del->close();
            }
            $message = 'Đã đặt lại mật khẩu thành công. Vui lòng đăng nhập.';
        }
    }
    // Làm mới CSRF sau khi POST
    $_SESSION['csrf_reset'] = bin2hex(random_bytes(16));
}

$hasToken = ($tokenOnUrl !== '' && $tokenValid);
?>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quên mật khẩu (bản fix)</title>
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <div class="login-glass" style="max-width:520px;margin:40px auto;">
        <h2 style="text-align:center;color:white;">Quên mật khẩu</h2>

        <?php if ($message): ?>
            <div style="color:#4caf50;text-align:center;margin:10px 0;"><?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div style="color:#ff6b6b;text-align:center;margin:10px 0;"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>

        <?php if (!$hasToken): ?>
            <!-- Bước 1: Nhập username để gửi email reset (không lộ enumeration) -->
            <form method="post" action="forgot_password.php" autocomplete="off">
                <input type="hidden" name="action" value="request">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Nhập username" style="width:100%;" required>
                </div>
                <div style="display:flex;gap:10px;align-items:center;">
                    <button type="submit" class="btn">Gửi liên kết đặt lại</button>
                    <a href="client_email.php" class="btn" style="width:auto;">Email Client</a>
                    <a href="index.php" style="color:#ddd;">Quay lại đăng nhập</a>
                </div>
            </form>
        <?php else: ?>
            <!-- Bước 2: Đặt mật khẩu mới (kiểm tra token + CSRF; không tin hidden username) -->
            <form method="post" action="forgot_password.php?temp-forgot-password-token=<?php echo urlencode($tokenOnUrl); ?>" autocomplete="off">
                <input type="hidden" name="action" value="reset">
                <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf_reset'], ENT_QUOTES, 'UTF-8'); ?>">
                <div class="form-group">
                    <input type="password" name="new_password" placeholder="Mật khẩu mới (>= 6 ký tự)" style="width:100%;" required>
                </div>
                <div style="display:flex;gap:10px;align-items:center;">
                    <button type="submit" class="btn">Đổi mật khẩu</button>
                    <a href="index.php" style="color:#ddd;">Quay lại đăng nhập</a>
                </div>
            </form>
        <?php endif; ?>
    </div>
</body>
</html>



