<?php
// HTTP Security Headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://code.jquery.com https://cdnjs.cloudflare.com https://stackpath.bootstrapcdn.com https://cdn.jsdelivr.net 'unsafe-inline'; style-src 'self' https://cdnjs.cloudflare.com https://stackpath.bootstrapcdn.com 'unsafe-inline'; font-src 'self' https://cdnjs.cloudflare.com data:; img-src 'self' data:; connect-src 'self' https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com;");
header('X-XSS-Protection: 1; mode=block');
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');

ini_set('session.cookie_samesite', 'lax');
// ini_set('session.cookie_secure', '1');
ini_set('session.cookie_httponly', '1');

session_start();
require_once 'config.php';

$error = "";

if($_SERVER['REQUEST_METHOD'] == "POST"){
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    if(empty($username) || empty($password)){
        $error = "Vui lòng điền đủ thông tin!";
    }else{
        $stmt = $config -> prepare("SELECT id, username, password, role, email FROM users WHERE username = ?");
        $stmt -> bind_param("s",$username);
        $stmt -> execute();
        $result = $stmt -> get_result();
        if($row = $result -> fetch_assoc()){
            if(password_verify($password, $row['password'])){
                // Bật 2FA: KHÔNG thiết lập phiên đăng nhập đầy đủ trước khi xác minh OTP
                // Lưu trạng thái chờ 2FA
                $_SESSION['pending_2fa_user_id'] = (int)$row['id'];
                $_SESSION['pending_2fa_username'] = $row['username'];
                $_SESSION['pending_2fa_role'] = $row['role'];
                $_SESSION['pending_2fa_expires'] = time() + 300; // 5 phút

                // Sinh OTP và lưu vào bảng emails (giả lập gửi email)
                $otp = (string)random_int(100000, 999999);
                $subject = '2FA code';
                $body = 'Your 2FA code is: ' . $otp;
                if ($ins = $config->prepare("INSERT INTO emails (username, email, subject, body, otp_code) VALUES (?,?,?,?,?)")) {
                    $ins->bind_param("sssss", $row['username'], $row['email'], $subject, $body, $otp);
                    $ins->execute();
                    $ins->close();
                }

                header("Location: verify_2fa.php");
                exit();
            }else{
                // FIX: Username enumeration - cùng error message
                $error = "Sai tên người dùng hoặc mật khẩu!";
            }
        }else{
            // FIX: Username enumeration - cùng error message
            $error = "Sai tên người dùng hoặc mật khẩu!";
        }
        $stmt -> close();
        $config -> close();
    }
}
include 'views/index.html'; 