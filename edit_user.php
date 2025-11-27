<?php
ini_set('session.cookie_samesite', 'lax');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_httponly', '1');

session_start();
include 'config.php';

// Kiểm tra quyền admin
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
    $id = isset($_POST['id']) ? (int)$_POST['id'] : 0;
    $username = isset($_POST['username']) ? trim($_POST['username']) : '';
    $role = isset($_POST['role']) ? $_POST['role'] : '';
    
    // Validate username
    if (empty($username) || !preg_match('/^[a-zA-Z0-9_]{3,30}$/', $username)) {
        $_SESSION['error'] = "Username không hợp lệ!";
        header('Location: user_manage.php');
        exit();
    }
    
    // Validate role
    if ($role !== 'user' && $role !== 'admin') {
        $_SESSION['error'] = "Role không hợp lệ!";
        header('Location: user_manage.php');
        exit();
    }

    // Cập nhật thông tin người dùng
    $sql = "UPDATE users SET username = ?, role = ? WHERE id = ?";
    $stmt = $config->prepare($sql);
    $stmt->bind_param("ssi", $username, $role, $id);

    if ($stmt->execute()) {
        $_SESSION['success'] = "Cập nhật người dùng thành công!";
    } else {
        $_SESSION['error'] = "Lỗi khi cập nhật người dùng!";
    }

    $stmt->close();
    header('Location: user_manage.php');
    exit();
}
?> 