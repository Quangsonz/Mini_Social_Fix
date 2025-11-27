<?php
session_start();
include 'config.php';

if (!isset($_SESSION['username'])) {
	header('Location: index.php');
	exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
	$newUsername = isset($_POST['new_username']) ? trim($_POST['new_username']) : '';
	$csrf = isset($_POST['csrf']) ? $_POST['csrf'] : '';

	if ($newUsername === '') {
		$_SESSION['error'] = 'Username mới không được để trống';
		header('Location: profile.php');
		exit();
	}
	
	// FIX: Kiểm tra CSRF token bắt buộc
	if (!isset($_SESSION['csrf']) || empty($_SESSION['csrf'])) {
		$_SESSION['error'] = 'CSRF token chưa được khởi tạo';
		header('Location: profile.php');
		exit();
	}
	
	if (!hash_equals($_SESSION['csrf'], $csrf)) {
		$_SESSION['error'] = 'CSRF token không hợp lệ';
		header('Location: profile.php');
		exit();
	}

	if (!preg_match('/^[a-zA-Z0-9_]{3,30}$/', $newUsername)) {
		$_SESSION['error'] = 'Username chỉ được chứa chữ, số, dấu gạch dưới và từ 3-30 ký tự';
		header('Location: profile.php');
		exit();
	}
	
	$check = $config->prepare("SELECT id FROM users WHERE username = ?");
	$check->bind_param('s', $newUsername);
	$check->execute();
	$check->store_result();
	if ($check->num_rows > 0) {
		$_SESSION['error'] = 'Username đã tồn tại';
		header('Location: profile.php');
		exit();
	}
	$check->close();
	
	// Lấy thông tin user hiện tại
	$currentUsername = $_SESSION['username'];


	$stmt = $config->prepare("UPDATE users SET username = ? WHERE username = ?");
	if ($stmt) {
		$stmt->bind_param('ss', $newUsername, $currentUsername);
		if ($stmt->execute()) {
			$_SESSION['username'] = $newUsername;
			$_SESSION['success'] = 'Đổi username thành công!';
		} else {
			$_SESSION['error'] = 'Không thể cập nhật username';
		}
		$stmt->close();
	} else {
		$_SESSION['error'] = 'Lỗi hệ thống khi chuẩn bị truy vấn';
	}

	header('Location: profile.php');
	exit();
}

// FIX: Chỉ cho phép POST method, từ chối GET
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
	$_SESSION['error'] = 'Method GET không được phép cho chức năng này';
	header('Location: profile.php');
	exit();
}

// FIX: Từ chối các method khác
$_SESSION['error'] = 'Method không được hỗ trợ';
header('Location: profile.php');
exit();
?>


