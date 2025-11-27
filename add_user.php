<?php
ini_set('session.cookie_samesite', 'lax');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_httponly', '1');

session_start();
include 'config.php';

if (!isset($_SESSION['username']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // FIX: CSRF protection
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    $csrf = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf'], $csrf)) {
        $_SESSION['error'] = 'CSRF token không hợp lệ';
        header('Location: user_manage.php');
        exit();
    }
    
    // FIX: Input validation
    $username = isset($_POST['username']) ? trim($_POST['username']) : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    $role = isset($_POST['role']) ? $_POST['role'] : '';
    
    // Validate username
    if (empty($username) || !preg_match('/^[a-zA-Z0-9_]{3,30}$/', $username)) {
        $_SESSION['error'] = "Username không hợp lệ! Phải có 3-30 ký tự, chỉ chứa chữ, số và dấu gạch dưới.";
        header('Location: user_manage.php');
        exit();
    }
    
    // Validate password
    if (empty($password) || strlen($password) < 6) {
        $_SESSION['error'] = "Password phải có ít nhất 6 ký tự!";
        header('Location: user_manage.php');
        exit();
    }
    
    // Validate role
    if ($role !== 'user' && $role !== 'admin') {
        $_SESSION['error'] = "Role không hợp lệ!";
        header('Location: user_manage.php');
        exit();
    }
    
    // Check if username already exists
    $check = $config->prepare("SELECT id FROM users WHERE username = ?");
    $check->bind_param('s', $username);
    $check->execute();
    $check->store_result();
    if ($check->num_rows > 0) {
        $_SESSION['error'] = 'Username đã tồn tại';
        $check->close();
        header('Location: user_manage.php');
        exit();
    }
    $check->close();

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $config->prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $username, $hashed_password, $role);

    if ($stmt->execute()) {
        $_SESSION['success'] = "Thêm người dùng thành công!";
    } else {
        $_SESSION['error'] = "Lỗi khi thêm người dùng!";
    }

    $stmt->close();
    header('Location: user_manage.php');
    exit();
}
?> 