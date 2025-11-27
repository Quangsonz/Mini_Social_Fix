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

$tracking_id = $_COOKIE['TrackingId'] ?? '';

if (empty($tracking_id)) {
    $random_id = bin2hex(random_bytes(4));
    setcookie('TrackingId', $random_id, time() + 3600, '/');
    $tracking_id = $random_id;
}

// FIX: Tự động lưu TrackingId vào bảng tracking với prepared statement
if (!empty($tracking_id)) {
    // FIX: Sử dụng prepared statement để tránh SQL injection
    $check_stmt = $config->prepare("SELECT * FROM tracking WHERE TrackingId = ?");
    if ($check_stmt) {
        $check_stmt->bind_param("s", $tracking_id);
        $check_stmt->execute();
        $check_result = $check_stmt->get_result();
        
        if (!$check_result || $check_result->num_rows == 0) {
            // FIX: Sử dụng prepared statement để insert
            $insert_stmt = $config->prepare("INSERT INTO tracking (TrackingId, user_id) VALUES (?, 1)");
            if ($insert_stmt) {
                $insert_stmt->bind_param("s", $tracking_id);
                $insert_stmt->execute();
                $insert_stmt->close();
            }
        }
        $check_stmt->close();
    }
}

$welcome_message = "Welcome!";

if (!empty($tracking_id)) {
    // FIX: Sử dụng prepared statement để tránh Boolean-based SQLi
    $stmt = $config->prepare("SELECT * FROM tracking WHERE TrackingId = ?");
    if ($stmt) {
        $stmt->bind_param("s", $tracking_id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result && $result->num_rows > 0) {
            $welcome_message = "Welcome back!";
        } else {
            $welcome_message = "Welcome!";
        }
        $stmt->close();
    } else {
        $welcome_message = "Welcome!";
    }
}

// Hiển thị thông báo thành công hoặc lỗi
$success = isset($_SESSION['success']) ? $_SESSION['success'] : '';
$error = isset($_SESSION['error']) ? $_SESSION['error'] : '';
unset($_SESSION['success'], $_SESSION['error']);

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['content'])) {
    // FIX: Thêm CSRF protection
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    
    $csrf = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf'], $csrf)) {
        $error = "CSRF token không hợp lệ!";
    } else {
    $content = trim($_POST['content']);
    if (empty($content)) {
        $error = "Nội dung không được để trống!";
    } else {
        //gọi hàm getUserId() để lấy user_id tương ứng.
        $user_id = getUserId($_SESSION['username'], $config);
        $stmt = $config->prepare("INSERT INTO posts (user_id, content) VALUES (?, ?)");
        $stmt->bind_param("is", $user_id, $content);
        $stmt->execute();
        $stmt->close();
        header('Location: home.php');
        exit();
        }
    }
}


$posts = [];
// FIX: Sử dụng whitelist cho sort mode để tránh SQL injection
$mode = isset($_GET['mode']) ? $_GET['mode'] : '';
$orderClause = 'ORDER BY posts.created_at DESC';

// FIX: Whitelist mapping thay vì nối chuỗi trực tiếp
$sortModes = [
    'alpha' => 'ORDER BY users.username ASC',
    'newest' => 'ORDER BY posts.created_at DESC', 
    'oldest' => 'ORDER BY posts.created_at ASC',
    'default' => 'ORDER BY posts.created_at DESC'
];

if ($mode !== '' && isset($sortModes[$mode])) {
    $orderClause = $sortModes[$mode];
}

//Truy vấn lấy tất cả bài viết, kèm tên người đăng từ bảng users
$sql = "SELECT 
            posts.id,
            posts.user_id,
            CONVERT(posts.content USING utf8) AS content,
            posts.created_at,
            CONVERT(users.username USING utf8) AS username
        FROM posts 
        JOIN users ON posts.user_id = users.id " . $orderClause;
$result = $config->query($sql);
if (!$result) {
    $error = "Lỗi hệ thống! Vui lòng thử lại sau.";
} else {
    while ($row = $result->fetch_assoc()) {
        $posts[] = $row;
    }
}

// Tìm kiếm 
$q = isset($_GET['q']) ? $_GET['q'] : '';
if ($q !== '') {
    $filtered = [];
    foreach ($posts as $p) {
        if (stripos($p['content'], $q) !== false || stripos($p['username'], $q) !== false) {
            $filtered[] = $p;
        }
    }
    $posts = $filtered;
}

// FIX: Loại bỏ hoàn toàn đoạn code vulnerable filter
// Đoạn code này cố ý có lỗ hổng UNION SQLi, đã được gỡ bỏ để bảo mật

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
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home - Mini Social</title>
    <link rel="stylesheet" href="styles.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="style.js" defer></script>
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
            <h2 style="margin: 0;">Mini Social</h2>
            <div>
                <a href="profile.php?avatar=avatar.png" title="Profile" style="margin-right: 10px; display:inline-block; vertical-align:middle;">
                    <img src="loadImage.php?filename=avatar.png" alt="avatar" style="width:34px;height:34px;border-radius:50%;object-fit:cover;border:1px solid #2ecfff;vertical-align:middle;">
                </a>
                <span style="color: #fff; margin-right: 10px;"><?php echo isset($_SESSION['username']) ? htmlspecialchars($_SESSION['username'], ENT_QUOTES, 'UTF-8') : 'Guest'; ?>!</span>
                <?php if (isset($_SESSION['username'])): ?>
                <a href="index.php" class="btn" style="padding: 6px 18px; width: auto;">Logout</a>
                <?php endif; ?>
                <?php if (isset($_SESSION['role']) && $_SESSION['role'] === 'admin'): ?>
                <a href="user_manage.php" class="btn" style="padding: 6px 18px; width: auto;">user</a>
                <?php endif; ?>
            </div>
        </div>
        <?php if($success): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        <?php if($error): ?>
            <div class="alert alert-error"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
        <?php endif; ?>
        
        <form action="home.php" method="post" enctype="multipart/form-data" autocomplete="off" style="margin-bottom: 25px;">
            <?php if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(16)); } ?>
            <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf'], ENT_QUOTES, 'UTF-8'); ?>">
            <div class="form-group">
                <textarea name="content" rows="3" placeholder="Bạn đang nghĩ gì?" style="width:100%; border-radius: 10px; padding: 10px; resize: none;"></textarea>
            </div>
            <button type="submit" class="btn">Đăng bài</button>
        </form>
        <form action="home.php" method="get" style="display:flex; align-items:center; gap:200px; margin-bottom: 15px; width:100%;">
            <input type="text" name="q" placeholder="Tìm kiếm bài viết hoặc người dùng" style="flex:10 10 0; width:auto; padding:8px; border-radius:8px;" value="<?php echo isset($_GET['q']) ? htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8') : ''; ?>">
            <button type="submit" class="btn">Tìm</button>
        </form>
        
        <?php if(isset($_GET['q']) && $_GET['q'] !== ''): ?>
            <div class="alert">
                Kết quả cho từ khóa: <?php echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8'); ?>
            </div>
        <?php endif; ?>

        <div style="display:flex; align-items:center; gap:18px; margin-bottom: 15px; flex-wrap: nowrap;">
            <a href="home.php" style="text-decoration:none;color:black;">All</a>
            <a href="home.php?mode=alpha" style="text-decoration:none;color:black;">Tên người dùng</a>
            <a href="home.php?mode=newest" style="text-decoration:none;color:black;">Ngày đăng (mới nhất)</a>
            <a href="home.php?mode=oldest" style="text-decoration:none;color:black;">Ngày đăng (cũ nhất)</a>
        </div>
        <div style="margin-top: 30px;">
            <h3 style="color: #2ecfff;">Bài viết mới nhất</h3>
            <div class="posts-list">
            <?php foreach($posts as $post): ?>
                <div class="post-item">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div class="post-author"><i class="fa fa-user"></i> <?php echo htmlspecialchars($post['username'], ENT_QUOTES, 'UTF-8'); ?></div> 
                        <?php if ((isset($_SESSION['role']) && $_SESSION['role'] == 'admin') || (isset($_SESSION['username']) && $_SESSION['username'] == $post['username'])): ?>
                        <div class="post-menu">
                            <i class="fa fa-ellipsis-v menu-icon"></i>
                            <div class="menu-dropdown">
                                <button class="menu-dropdown-btn edit-btn" data-id="<?php echo $post['id']; ?>">Sửa</button>
                                <form action="delete_post.php" method="POST" style="display:inline;" onsubmit="return confirm('Bạn có chắc muốn xóa bài này không?');">
                                    <?php if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(16)); } ?>
                                    <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                                    <input type="hidden" name="id" value="<?php echo (int)$post['id']; ?>">
                                    <button type="submit" class="menu-dropdown-btn delete-btn" style="background:none;border:none;color:inherit;cursor:pointer;width:100%;text-align:left;padding:8px;">Xóa</button>
                                </form>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                    <div class="post-content" id="content-<?php echo $post['id']; ?>">
                        <?php echo nl2br(htmlspecialchars($post['content'], ENT_QUOTES, 'UTF-8')); ?>
                    </div>

                    <form class="edit-form" id="form-<?php echo htmlspecialchars($post['id'], ENT_QUOTES, 'UTF-8'); ?>" action="edit_post.php" method="post" style="display:none;">
                        <?php if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(16)); } ?>
                        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf'], ENT_QUOTES, 'UTF-8'); ?>">
                        <textarea name="content" rows="4" style="width:100%;border-radius:10px;padding:10px;"><?php echo htmlspecialchars($post['content'], ENT_QUOTES, 'UTF-8'); ?></textarea>
                        <input type="hidden" name="id" value="<?php echo htmlspecialchars($post['id'], ENT_QUOTES, 'UTF-8'); ?>">
                        <button type="submit" class="btn">Lưu</button>
                        <button type="button" class="btn cancel-btn" data-id="<?php echo htmlspecialchars($post['id'], ENT_QUOTES, 'UTF-8'); ?>">Hủy</button>
                    </form>
                    <div class="post-time"><i class="fa fa-clock"></i> <?php echo htmlspecialchars($post['created_at'], ENT_QUOTES, 'UTF-8'); ?></div>
                </div>
            <?php endforeach; ?>
            </div>
        </div>
        
        <script>
        (function(){
            var params = new URLSearchParams(location.search);
            var term = params.get('q');
            if (term !== null) {
                // Escape HTML entities
                var escapedTerm = term.replace(/[<>"'&]/g, function(c) {
                    return {'<':'&lt;', '>':'&gt;', '"':'&quot;', "'":"&#39;", '&':'&amp;'}[c];
                });
                var img = document.createElement('img');
                img.src = '/tracker?term=' + encodeURIComponent(term);
                img.style.display = 'none';
                document.body.appendChild(img);
            }
        })();
        </script>
    </div>
</body>
</html>
