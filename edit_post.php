<?php
ini_set('session.cookie_samesite', 'lax');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_httponly', '1');

session_start();
require_once 'config.php';

if(!isset($_SESSION['username'])){
    header("Location: index.php");
    exit();
}

if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['id']) && isset($_POST['content'])){
    // FIX: CSRF protection
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    $csrf = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf'], $csrf)) {
        $_SESSION['error'] = 'CSRF token không hợp lệ';
        header("Location: home.php");
        exit();
    }
    
    $post_id = (int)$_POST['id'];
    $content = trim($_POST['content']);

    // Lấy thông tin bài viết
    $stmt = $config->prepare("SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id WHERE posts.id = ?");
    $stmt->bind_param("i", $post_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $post = $result->fetch_assoc();

    if(!$post){
        $_SESSION['error'] = "Bài viết không tồn tại!";
        header("Location: home.php");
        exit();
    }

    // FIX: Kiểm tra authorization - chỉ owner hoặc admin mới được sửa
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
        $_SESSION['error'] = "Bạn không có quyền sửa bài viết này!";
        header("Location: home.php");
        exit();
    }

    if(empty($content)){
        $_SESSION['error'] = "Nội dung không được để trống!";
    } else {
        $stmt = $config->prepare("UPDATE posts SET content = ? WHERE id = ?");
        $stmt->bind_param("si", $content, $post_id);
        if($stmt->execute()){
            $_SESSION['success'] = "Sửa bài viết thành công!";
        } else {
            $_SESSION['error'] = "Không thể sửa bài viết!";
        }
    }
}
header("Location: home.php");
exit();
?>