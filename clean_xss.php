<?php
$config = new mysqli('localhost', 'root', '', 'mini_social');
if($config->connect_error) {
    die('Kết nối thất bại: ' . $config->connect_error);
}

echo "Đang xóa các bài viết chứa XSS...\n";

// Xóa các bài viết chứa payload XSS
$result = $config->query("DELETE FROM posts WHERE content LIKE '%<script>%' OR content LIKE '%<img%' OR content LIKE '%<svg%' OR content LIKE '%javascript:%'");

if($result) {
    echo "Đã xóa " . $config->affected_rows . " bài viết chứa XSS\n";
} else {
    echo "Lỗi: " . $config->error . "\n";
}

// Xóa session để tránh thông báo XSS
session_start();
unset($_SESSION['success']);
unset($_SESSION['error']);

echo "Đã xóa session success/error\n";
echo "Hoàn thành!\n";

$config->close();
?>
