<?php
// HTTP Security Headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://code.jquery.com https://cdnjs.cloudflare.com https://stackpath.bootstrapcdn.com https://cdn.jsdelivr.net 'unsafe-inline'; style-src 'self' https://cdnjs.cloudflare.com https://stackpath.bootstrapcdn.com 'unsafe-inline'; font-src 'self' https://cdnjs.cloudflare.com data:; img-src 'self' data:; connect-src 'self' https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com;");
header('X-XSS-Protection: 1; mode=block');
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');

ini_set('session.cookie_samesite', 'lax');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_httponly', '1');

session_start();
include 'config.php';

if (!isset($_SESSION['username'])) {
	header('Location: index.php');
	exit();
}

// ✅ FIX IDOR: Chỉ cho phép xem profile của chính user đang login
// Không cho phép xem profile người khác qua parameter ?id=X
$username = $_SESSION['username'];
$stmt = $config->prepare("SELECT id, username, email, role FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();
$user_info = $result->fetch_assoc();
$stmt->close();

// Nếu không tìm thấy user (trường hợp bất thường), redirect về login
if (!$user_info) {
	session_destroy();
	header('Location: index.php');
	exit();
}

// FIX: Validate và sanitize avatar parameter
$avatar = isset($_GET['avatar']) ? $_GET['avatar'] : 'avatar.png';
// Whitelist allowed filenames để tránh path traversal
$allowed_avatars = ['avatar.png'];
$avatar = basename($avatar); // Lấy tên file, loại bỏ path traversal
if (!in_array($avatar, $allowed_avatars)) {
    $avatar = 'avatar.png'; // Default nếu không hợp lệ
}
// Show flash messages
$success = isset($_SESSION['success']) ? $_SESSION['success'] : '';
$error = isset($_SESSION['error']) ? $_SESSION['error'] : '';
unset($_SESSION['success'], $_SESSION['error']);

// CSRF token for POST (lab-like): enforce on POST only, GET will bypass in handler
if (empty($_SESSION['csrf'])) {
	$_SESSION['csrf'] = bin2hex(random_bytes(16));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>User Profile</title>
	<link rel="stylesheet" href="styles.css">
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
	<div class="galaxy-bg">
		<div class="circle blue1"></div>
		<div class="circle blue2"></div>
		<div class="circle orange1"></div>
		<div class="circle orange2"></div>
	</div>
	<div class="home-glass">
		<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
			<h2 style="margin: 0;">User Profile</h2>
			<div>
				<a href="home.php" class="btn" style="padding: 6px 18px; width: auto;">Home</a>
				<a href="login.php" class="btn" style="padding: 6px 18px; width: auto;">Logout</a>
			</div>
		</div>

		<?php if ($success): ?>
			<div class="alert alert-success" style="margin-bottom: 16px; color: #0f0;">
				<?php echo htmlspecialchars($success); ?>
			</div>
		<?php endif; ?>

		<?php if ($error): ?>
			<div class="alert alert-danger" style="margin-bottom: 16px; color: #ff2e63;">
				<?php echo htmlspecialchars($error); ?>
			</div>
		<?php endif; ?>
		
		<!-- Hiển thị thông tin user -->
		<?php if ($user_info): ?>
		<div style="margin-bottom:20px;">
			<h3 style="color:#fff;">Thông tin tài khoản</h3>
			<p style="color:#fff;"><strong>User ID:</strong> <?php echo htmlspecialchars($user_info['id']); ?></p>
			<p style="color:#fff;"><strong>Username:</strong> <?php echo htmlspecialchars($user_info['username']); ?></p>
			<p style="color:#fff;"><strong>Email:</strong> <?php echo htmlspecialchars($user_info['email']); ?></p>
			<p style="color:#fff;"><strong>Role:</strong> <?php echo htmlspecialchars($user_info['role']); ?></p>
		</div>
		<?php endif; ?>
		
		<div style="display:flex; align-items:center; gap:20px;">
			<img src="loadImage.php?filename=<?php echo htmlspecialchars($avatar, ENT_QUOTES, 'UTF-8'); ?>" alt="avatar" style="width:120px;height:120px;border-radius:50%;object-fit:cover;border:2px solid #2ecfff;">
			<div>
				<div style="color:#fff;font-size:20px;font-weight:600;">
					<i class="fa fa-user"></i> <?php echo htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8'); ?>
				</div>
				<form action="change_username.php" method="POST" style="margin-top:12px; display:flex; gap:8px; align-items:center;">
					<input type="text" name="new_username" placeholder="Nhập username mới" required style="padding:10px; border:1px solid rgba(255,255,255,0.2); border-radius:5px; background: rgba(255,255,255,0.1); color:#fff;">
					<input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf']); ?>">
					<button type="submit" class="btn" style="padding: 8px 18px;">Đổi username</button>
				</form>
			</div>
		</div>
	</div>
</body>
</html>


