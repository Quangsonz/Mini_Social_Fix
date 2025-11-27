<?php

ini_set('session.cookie_samesite', 'lax');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_httponly', '1');

session_start();
require_once 'config.php';

// Kiểm tra đăng nhập
if(!isset($_SESSION['username'])) {
    header("Location: index.php");
    exit();
}

// FIX: Chỉ nhận POST method
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: home.php");
    exit();
}

// FIX: Kiểm tra CSRF token
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}
$csrf = $_POST['csrf'] ?? '';
if (!hash_equals($_SESSION['csrf'], $csrf)) {
    $_SESSION['error'] = 'CSRF token không hợp lệ';
    header("Location: home.php");
    exit();
}

// FIX: Validate input - chỉ nhận integer từ POST
$post_id = isset($_POST['id']) ? (int)$_POST['id'] : 0;
if ($post_id <= 0) {
    $_SESSION['error'] = "ID bài viết không hợp lệ!";
    header("Location: home.php");
    exit();
}

// Kiểm tra xem bài viết có tồn tại không
$stmt = $config->prepare("SELECT * FROM posts WHERE id = ?");
$stmt->bind_param("i", $post_id);
$stmt->execute();
$result = $stmt->get_result();
$post = $result->fetch_assoc();

if(!$post) {
    $_SESSION['error'] = "Bài viết không tồn tại!";
    header("Location: home.php");
    exit();
}

// FIX: Kiểm tra authorization - chỉ owner hoặc admin mới được xóa
function getUserId($username, $config) {
    $stmt = $config->prepare("SELECT id FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $id = null;
    $stmt->bind_result($id);
    $stmt->fetch();
    $stmt->close();
    return $id;
}

$is_owner = ($post['user_id'] == getUserId($_SESSION['username'], $config));
$is_admin = (isset($_SESSION['role']) && $_SESSION['role'] === 'admin');

if (!$is_owner && !$is_admin) {
    $_SESSION['error'] = "Bạn không có quyền xóa bài viết này!";
    header("Location: home.php");
    exit();
}

// Xóa bài viết
$stmt = $config->prepare("DELETE FROM posts WHERE id = ?");
$stmt->bind_param("i", $post_id);
if($stmt->execute()) {
    $_SESSION['success'] = "Đã xóa bài viết thành công!";
} else {
    $_SESSION['error'] = "Không thể xóa bài viết!";
}
$stmt->close();

header("Location: home.php");
exit();