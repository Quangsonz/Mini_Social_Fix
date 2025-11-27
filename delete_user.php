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
    
    if ($id <= 0) {
        $_SESSION['error'] = "ID không hợp lệ!";
        header('Location: user_manage.php');
        exit();
    }

    // Xóa tất cả bài viết của user trước
    $stmt = $config->prepare("DELETE FROM posts WHERE user_id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $stmt->close();

    // Sau đó mới xóa user
    $stmt = $config->prepare("DELETE FROM users WHERE id = ?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute()) {
        $_SESSION['success'] = "Xóa người dùng thành công!";
    } else {
        $_SESSION['error'] = "Lỗi khi xóa người dùng!";
    }
    $stmt->close();
    header('Location: user_manage.php');
    exit();
}
?> 