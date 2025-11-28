# Mini Social - Secure Version

## 📖 GIỚI THIỆU DỰ ÁN

**Mini Social** là một dự án mạng xã hội mini được phát triển với mục đích **giáo dục về bảo mật web**. Dự án bao gồm 2 phiên bản:

- **mini_social**: Phiên bản có chứa các lỗ hổng bảo mật (vulnerable version) - dùng làm môi trường lab để học và thực hành tấn công
- **mini_social-fix**: Phiên bản đã được vá tất cả lỗ hổng bảo mật (secure version) - minh họa các phương pháp phòng chống

### 🎯 Mục đích dự án

1. **Học tập bảo mật web**: Cung cấp môi trường thực hành để hiểu rõ các lỗ hổng bảo mật phổ biến (SQLi, XSS, CSRF, IDOR, Path Traversal, v.v.)
2. **So sánh code vulnerable vs secure**: Giúp developers nhận biết code không an toàn và cách fix đúng chuẩn
3. **Thực hành penetration testing**: Môi trường an toàn để test các kỹ thuật tấn công và phòng thủ

### ⚙️ Công nghệ sử dụng

- **Backend**: PHP 7.4+
- **Database**: MySQL/MariaDB
- **Frontend**: HTML5, CSS3, JavaScript (jQuery)
- **Security Headers**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- **Session Security**: httponly, secure, samesite flags

---

## 🛡️ CÁC LỖ HỔNG ĐÃ ĐƯỢC VÁ VÀ CÁCH FIX

File này minh họa **phiên bản secure (mini_social-fix)** - tất cả các lỗ hổng đã được sửa chữa theo best practices.

---

## 1️⃣ index.php - TRANG ĐĂNG NHẬP

### 🔒 Security Headers (Dòng 2-5)

**Code đã fix:**
\`\`\`php
// Dòng 2-5: Thêm HTTP Security Headers
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://code.jquery.com https://cdnjs.cloudflare.com https://stackpath.bootstrapcdn.com https://cdn.jsdelivr.net 'unsafe-inline'; style-src 'self' https://cdnjs.cloudflare.com https://stackpath.bootstrapcdn.com 'unsafe-inline'; font-src 'self' https://cdnjs.cloudflare.com data:; img-src 'self' data:; connect-src 'self' https://cdn.jsdelivr.net https://stackpath.bootstrapcdn.com;");
header('X-XSS-Protection: 1; mode=block');
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
\`\`\`

**Giải thích:**
- **CSP (Content-Security-Policy)**: Chỉ cho phép load resources từ domain được whitelist, ngăn chặn XSS attacks
- **X-XSS-Protection**: Kích hoạt XSS filter của browser
- **X-Frame-Options: SAMEORIGIN**: Ngăn chặn clickjacking attacks
- **X-Content-Type-Options: nosniff**: Ngăn browser đoán MIME type, tránh MIME confusion attacks

---

### 🔒 Session Cookie Security (Dòng 7-9)

**Code đã fix:**
\`\`\`php
// Dòng 7-9: Bật các security flags cho session cookie
ini_set('session.cookie_samesite', 'lax');
// ini_set('session.cookie_secure', '1'); // Uncomment khi dùng HTTPS
ini_set('session.cookie_httponly', '1');
\`\`\`

**Giải thích:**
- **httponly=1**: Cookie không thể đọc được qua JavaScript (document.cookie), ngăn XSS steal cookie
- **secure=1**: Cookie chỉ được gửi qua HTTPS (nên bật khi production có SSL)
- **samesite=lax**: Ngăn chặn CSRF attacks bằng cách giới hạn cookie chỉ gửi khi same-site requests

---

### ✅ FIX #1: SQL Injection - Sử dụng Prepared Statement (Dòng 24-30)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Nối chuỗi trực tiếp vào SQL
$sql = "SELECT * FROM users WHERE username = '" . $username . "' AND password = '" . $password . "'";
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 24-30: Sử dụng prepared statement để tránh SQL injection
$stmt = $config -> prepare("SELECT id, username, password, role, email FROM users WHERE username = ?");
$stmt -> bind_param("s",$username);
$stmt -> execute();
$result = $stmt -> get_result();
if($row = $result -> fetch_assoc()){
    if(password_verify($password, $row['password'])){
        // ... logic xác thực
\`\`\`

**Giải thích:**
- **Prepared Statement**: Tách biệt SQL structure và user input → Database engine tự escape special characters
- **bind_param("s", $username)**: Bind parameter với type `s` (string), đảm bảo $username được xử lý an toàn
- **password_verify()**: Verify password hash thay vì so sánh plaintext
- **Ngăn chặn**: SQLi payloads như `admin' --` hoặc `' OR 1=1 --` không còn hiệu lực

---

### ✅ FIX #2: 2FA Bypass - Đúng Flow Xác Thực (Dòng 32-45)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Set session trước khi verify 2FA
$_SESSION['username'] = $row['username'];
$_SESSION['role'] = $row['role'];
$_SESSION['2fa_verified'] = false;
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 32-45: Không set session chính thức, chỉ lưu pending state
$_SESSION['pending_2fa_user_id'] = (int)$row['id'];
$_SESSION['pending_2fa_username'] = $row['username'];
$_SESSION['pending_2fa_role'] = $row['role'];
$_SESSION['pending_2fa_expires'] = time() + 300; // 5 phút hết hạn

// Sinh OTP và lưu vào DB (giả lập gửi email)
$otp = (string)random_int(100000, 999999);
$subject = '2FA code';
$body = 'Your 2FA code is: ' . $otp;
if ($ins = $config->prepare("INSERT INTO emails (username, email, subject, body, otp_code) VALUES (?,?,?,?,?)")) {
    $ins->bind_param("sssss", $row['username'], $row['email'], $subject, $body, $otp);
    $ins->execute();
}

header("Location: verify_2fa.php");
exit();
\`\`\`

**Giải thích:**
- **Pending state**: Lưu thông tin tạm thời vào `pending_2fa_*` thay vì set `$_SESSION['username']` ngay
- **OTP expires**: Thêm timeout 5 phút cho pending state để tránh session hijacking
- **Chỉ set session chính thức sau khi verify OTP thành công** → User không thể bypass bằng cách truy cập trực tiếp vào trang khác

---

### ✅ FIX #3: Username Enumeration - Cùng Error Message (Dòng 51-57)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Error message khác nhau
if ($resultUser && $resultUser->num_rows > 0) {
    $error = "Invalid username or password."; // có dấu chấm
} else {
    $error = "Invalid username or password "; // có khoảng trắng
}
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 51-57: Cùng error message cho cả 2 trường hợp
if(password_verify($password, $row['password'])){
    // ... login thành công
}else{
    // FIX: Username enumeration - cùng error message
    $error = "Sai tên người dùng hoặc mật khẩu!";
}
\`\`\`

và:

\`\`\`php
}else{
    // FIX: Username enumeration - cùng error message
    $error = "Sai tên người dùng hoặc mật khẩu!";
}
\`\`\`

**Giải thích:**
- **Cùng 1 message cho cả 2 case**: Username không tồn tại HOẶC password sai → Attacker không thể biết được username có tồn tại hay không
- **Ngăn chặn**: Không thể enumerate users bằng cách phân tích error messages

---

## 2️⃣ register.php - TRANG ĐĂNG KÝ

### ✅ FIX #4: Password Hashing - Sử dụng PASSWORD_DEFAULT (Dòng 35)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Lưu password plaintext
$stmt = $config -> prepare("INSERT INTO users (username, email, password, role) VALUES (?,?,?,?)");
$stmt -> bind_param("ssss",$username, $email, $password, $role);
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 35: Hash password trước khi lưu vào DB
$password = password_hash($password, PASSWORD_DEFAULT);
$stmt = $config -> prepare("INSERT INTO users ( username, password, role) VALUES (?,?,?)");
$stmt -> bind_param("sss",$username, $password, $role);
\`\`\`

**Giải thích:**
- **password_hash()**: Sử dụng bcrypt algorithm (PASSWORD_DEFAULT) với salt tự động
- **Bcrypt**: Slow hashing algorithm, khó brute-force (có cost factor)
- **Ngăn chặn**: Nếu database bị leak, password vẫn an toàn (không thể reverse bcrypt hash)

---

### ✅ FIX #5: XSS Prevention - htmlspecialchars() (Dòng 73, 94, 98)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Output trực tiếp user input
<input type="text" name="username" value="<?php echo $_POST['username'] ?? ''; ?>">
<?php if($error): ?>
    <div class="alert"><?php echo $error; ?></div>
<?php endif; ?>
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 73: Encode HTML entities khi output
<input type="text" id="username" name="username" value="<?php echo htmlspecialchars($_POST['username'] ?? '', ENT_QUOTES, 'UTF-8'); ?>" placeholder="Username" required>

// Dòng 94, 98: Encode error/success messages
<?php if($error): ?>
    <div class="alert alert-danger"><?php echo htmlspecialchars($error, ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>
<?php if($success): ?>
    <div class="alert alert-success"><?php echo htmlspecialchars($success, ENT_QUOTES, 'UTF-8'); ?></div>
<?php endif; ?>
\`\`\`

**Giải thích:**
- **htmlspecialchars()**: Convert các ký tự đặc biệt HTML thành entities (`<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`, v.v.)
- **ENT_QUOTES**: Encode cả single và double quotes
- **UTF-8**: Đảm bảo encoding đúng với charset database
- **Ngăn chặn**: XSS payloads như `<script>alert(1)</script>` sẽ được hiển thị dưới dạng text thuần thay vì execute

---

## 3️⃣ home.php - TRANG CHỦ

### ✅ FIX #6: Boolean-based SQLi - Prepared Statement cho TrackingId (Dòng 25-38)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Nối chuỗi trực tiếp với cookie
$check_sql = "SELECT * FROM tracking WHERE TrackingId = '" . $tracking_id . "'";
$sql = "SELECT * FROM tracking WHERE TrackingId = '" . $tracking_id . "'";
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 25-38: Sử dụng prepared statement cho TrackingId cookie
$check_stmt = $config->prepare("SELECT * FROM tracking WHERE TrackingId = ?");
if ($check_stmt) {
    $check_stmt->bind_param("s", $tracking_id);
    $check_stmt->execute();
    $check_result = $check_stmt->get_result();
    
    if (!$check_result || $check_result->num_rows == 0) {
        $insert_stmt = $config->prepare("INSERT INTO tracking (TrackingId, user_id) VALUES (?, 1)");
        if ($insert_stmt) {
            $insert_stmt->bind_param("s", $tracking_id);
            $insert_stmt->execute();
        }
    }
}
\`\`\`

và:

\`\`\`php
// Dòng 48-61: Prepared statement cho welcome message logic
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
}
\`\`\`

**Giải thích:**
- **Prepared statement cho cookie value**: Cookie `TrackingId` được bind an toàn vào query
- **Ngăn chặn Boolean-based SQLi**: Payloads như `xyz' OR 1=1 --` không còn exploit được
- **Tất cả queries liên quan đến TrackingId đều dùng prepared statement**

---

### ✅ FIX #7: CSRF Protection - Token Validation (Dòng 69-77)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Không có CSRF protection
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['content'])) {
    $content = trim($_POST['content']);
    // ... lưu post
}
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 69-77: Thêm CSRF token validation
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['content'])) {
    // Sinh CSRF token nếu chưa có
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(16));
    }
    
    // Validate CSRF token
    $csrf = $_POST['csrf'] ?? '';
    if (!hash_equals($_SESSION['csrf'], $csrf)) {
        $error = "CSRF token không hợp lệ!";
    } else {
        // ... logic lưu post
    }
}
\`\`\`

và trong HTML form (dòng 174-175):

\`\`\`php
<?php if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(16)); } ?>
<input type="hidden" name="csrf" value="<?php echo htmlspecialchars($_SESSION['csrf'], ENT_QUOTES, 'UTF-8'); ?>">
\`\`\`

**Giải thích:**
- **CSRF Token**: Random string 32 hex chars (16 bytes) được sinh mỗi session
- **hash_equals()**: So sánh constant-time để tránh timing attacks
- **Hidden field**: Token được gửi cùng form POST để server validate
- **Ngăn chặn**: Attacker không thể tạo form giả để submit vì không biết CSRF token

---

### ✅ FIX #8: UNION-based SQLi - Whitelist cho Sort Mode (Dòng 90-100)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Nối user input trực tiếp vào ORDER BY clause
$mode = isset($_GET['mode']) ? $_GET['mode'] : '';
$orderClause = 'ORDER BY posts.created_at DESC';
if ($mode !== '') {
    $orderClause = $mode; // Nguy hiểm!
}
$sql = "SELECT ... FROM posts ... " . $orderClause;
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 90-100: Sử dụng whitelist mapping thay vì nối chuỗi
$mode = isset($_GET['mode']) ? $_GET['mode'] : '';
$orderClause = 'ORDER BY posts.created_at DESC';

// Whitelist các giá trị hợp lệ
$sortModes = [
    'alpha' => 'ORDER BY users.username ASC',
    'newest' => 'ORDER BY posts.created_at DESC', 
    'oldest' => 'ORDER BY posts.created_at ASC',
    'default' => 'ORDER BY posts.created_at DESC'
];

// Chỉ chấp nhận giá trị trong whitelist
if ($mode !== '' && isset($sortModes[$mode])) {
    $orderClause = $sortModes[$mode];
}

$sql = "SELECT ... FROM posts JOIN users ... " . $orderClause;
\`\`\`

**Giải thích:**
- **Whitelist approach**: Chỉ chấp nhận các giá trị được định nghĩa trước (alpha, newest, oldest)
- **Không nối trực tiếp user input**: Nếu `$mode` không nằm trong whitelist, dùng default value
- **Ngăn chặn UNION-based SQLi**: Payloads như `?mode=UNION SELECT 1,2,3,4,5 FROM users--` sẽ bị ignore và dùng default ORDER BY

---

### ✅ FIX #9: Stored XSS Prevention - htmlspecialchars() Output (Dòng 188, 189, 200, 211, 221)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Output trực tiếp content từ database
<div class="post-author"><?php echo $post['username']; ?></div>
<div class="post-content"><?php echo nl2br($post['content']); ?></div>
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 188-189: Encode username và content khi hiển thị
<div class="post-author"><i class="fa fa-user"></i> <?php echo htmlspecialchars($post['username'], ENT_QUOTES, 'UTF-8'); ?></div>

<div class="post-content" id="content-<?php echo $post['id']; ?>">
    <?php echo nl2br(htmlspecialchars($post['content'], ENT_QUOTES, 'UTF-8')); ?>
</div>

// Dòng 200, 211, 221: Encode tất cả data attributes và values
<form class="edit-form" id="form-<?php echo htmlspecialchars($post['id'], ENT_QUOTES, 'UTF-8'); ?>">
    <textarea name="content"><?php echo htmlspecialchars($post['content'], ENT_QUOTES, 'UTF-8'); ?></textarea>
    <input type="hidden" name="id" value="<?php echo htmlspecialchars($post['id'], ENT_QUOTES, 'UTF-8'); ?>">
</form>

<div class="post-time"><?php echo htmlspecialchars($post['created_at'], ENT_QUOTES, 'UTF-8'); ?></div>
\`\`\`

**Giải thích:**
- **Encode mọi output từ database**: Username, content, timestamps đều được encode
- **nl2br()**: Convert newlines thành `<br>` sau khi đã encode (giữ format text)
- **Ngăn chặn Stored XSS**: Payloads như `<script>alert(1)</script>` được lưu trong DB nhưng hiển thị dưới dạng text thay vì execute

---

### ✅ FIX #10: Reflected XSS Prevention - Escape Search Query (Dòng 184, 230-238)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Reflected XSS trong search query
<?php if(isset($_GET['q']) && $_GET['q'] !== ''): ?>
    <div class="alert">Kết quả cho từ khóa: <?php echo $_GET['q']; ?></div>
<?php endif; ?>
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 184: Encode search query trong input value
<input type="text" name="q" placeholder="Tìm kiếm..." value="<?php echo isset($_GET['q']) ? htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8') : ''; ?>">

// Dòng 185: Encode search query trong alert message
<?php if(isset($_GET['q']) && $_GET['q'] !== ''): ?>
    <div class="alert">
        Kết quả cho từ khóa: <?php echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8'); ?>
    </div>
<?php endif; ?>

// Dòng 230-238: JavaScript cũng escape HTML entities
<script>
(function(){
    var params = new URLSearchParams(location.search);
    var term = params.get('q');
    if (term !== null) {
        // Escape HTML entities
        var escapedTerm = term.replace(/[<>"'&]/g, function(c) {
            return {'<':'&lt;', '>':'&gt;', '"':'&quot;', "'":"&#39;", '&':'&amp;'}[c];
        });
        // ... tracking code
    }
})();
</script>
\`\`\`

**Giải thích:**
- **Server-side encoding**: PHP encode parameter `q` trước khi output vào HTML
- **Client-side encoding**: JavaScript cũng escape các ký tự đặc biệt trước khi xử lý
- **Ngăn chặn Reflected XSS**: URL như `?q=<script>alert(1)</script>` không thể execute code

---

## 4️⃣ profile.php - TRANG PROFILE

### ✅ FIX #11: IDOR Prevention - Chỉ View Profile của Chính Mình (Dòng 16-28)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Có thể xem profile bất kỳ user nào
$view_id = isset($_GET['id']) ? intval($_GET['id']) : 0;
if ($view_id) {
    $stmt = $config->prepare("SELECT id, username, email, role FROM users WHERE id = ?");
    $stmt->bind_param("i", $view_id);
    // ... không check ownership
}
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 16-28: Chỉ cho phép xem profile của chính user đang login
$username = $_SESSION['username'];
$stmt = $config->prepare("SELECT id, username, email, role FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();
$user_info = $result->fetch_assoc();

// Nếu không tìm thấy user, logout
if (!$user_info) {
    session_destroy();
    header('Location: index.php');
    exit();
}
\`\`\`

**Giải thích:**
- **Bỏ parameter `?id=X`**: Không cho phép truyền user_id qua URL
- **Lấy thông tin từ session**: Dùng `$_SESSION['username']` để query user hiện tại
- **Ngăn chặn IDOR**: User không thể xem profile của người khác bằng cách thay đổi `?id=1`, `?id=2`, v.v.

---

### ✅ FIX #12: Path Traversal Prevention - Whitelist Avatar (Dòng 30-36)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Truyền trực tiếp filename vào loadImage.php
$avatar = isset($_GET['avatar']) ? $_GET['avatar'] : 'avatar.png';
// Không có validation
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 30-36: Validate và whitelist avatar filenames
$avatar = isset($_GET['avatar']) ? $_GET['avatar'] : 'avatar.png';

// Whitelist các file được phép
$allowed_avatars = ['avatar.png'];
$avatar = basename($avatar); // Loại bỏ path traversal attempts

if (!in_array($avatar, $allowed_avatars)) {
    $avatar = 'avatar.png'; // Default nếu không hợp lệ
}
\`\`\`

**Giải thích:**
- **basename()**: Chỉ lấy tên file, loại bỏ path components (`../config.php` → `config.php`)
- **Whitelist check**: Chỉ chấp nhận các filename trong array `$allowed_avatars`
- **Default fallback**: Nếu không hợp lệ, dùng `avatar.png`
- **Ngăn chặn Path Traversal**: Payloads như `?avatar=../config.php` hoặc `?avatar=../../etc/passwd` không thể exploit

---

## 5️⃣ change_username.php - ĐỔI USERNAME

### ✅ FIX #13: CSRF Protection - Bắt Buộc CSRF Token (Dòng 14-23)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Chỉ check CSRF khi có parameter csrf (có thể bypass bằng cách bỏ qua)
if ($csrf !== '' && (!isset($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $csrf))) {
    $_SESSION['error'] = 'CSRF token không hợp lệ';
}
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 14-23: Kiểm tra CSRF token BẮT BUỘC, không cho phép bypass
// Kiểm tra CSRF token đã được khởi tạo chưa
if (!isset($_SESSION['csrf']) || empty($_SESSION['csrf'])) {
    $_SESSION['error'] = 'CSRF token chưa được khởi tạo';
    header('Location: profile.php');
    exit();
}

// Validate CSRF token (bắt buộc)
if (!hash_equals($_SESSION['csrf'], $csrf)) {
    $_SESSION['error'] = 'CSRF token không hợp lệ';
    header('Location: profile.php');
    exit();
}
\`\`\`

**Giải thích:**
- **Check CSRF token bắt buộc**: Không còn điều kiện `if ($csrf !== '')` → phải có token mới pass
- **Validate session csrf exists**: Check cả `isset()` và `empty()` để đảm bảo token đã được init
- **Ngăn chặn CSRF bypass**: Attacker không thể bypass bằng cách gửi request không có field `csrf`

---

### ✅ FIX #14: GET Method Rejection - Chỉ Chấp Nhận POST (Dòng 62-67)

**Code vulnerable (mini_social trong change_username2.php):**
\`\`\`php
// VULNERABLE: Cho phép GET method
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $newUsername = isset($_GET['new_username']) ? trim($_GET['new_username']) : '';
    // ... update username
}
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 62-67: Từ chối GET method, chỉ chấp nhận POST
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $_SESSION['error'] = 'Method GET không được phép cho chức năng này';
    header('Location: profile.php');
    exit();
}

// Từ chối các method khác
$_SESSION['error'] = 'Method không được hỗ trợ';
header('Location: profile.php');
exit();
\`\`\`

**Giải thích:**
- **Chỉ chấp nhận POST**: State-changing operations phải dùng POST method
- **Reject GET explicitly**: Hiển thị error message khi nhận GET request
- **Ngăn chặn GET-based CSRF**: Attacker không thể tạo link `<a href="change_username.php?new_username=HACKED">` để CSRF

---

### ✅ FIX #15: Input Validation - Username Regex (Dòng 25-29)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Không validate format username
if ($newUsername === '') {
    // chỉ check empty
}
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 25-29: Validate username format với regex
if (!preg_match('/^[a-zA-Z0-9_]{3,30}$/', $newUsername)) {
    $_SESSION['error'] = 'Username chỉ được chứa chữ, số, dấu gạch dưới và từ 3-30 ký tự';
    header('Location: profile.php');
    exit();
}
\`\`\`

**Giải thích:**
- **Regex validation**: Username chỉ chấp nhận `a-zA-Z0-9_` và độ dài 3-30 ký tự
- **Ngăn chặn special characters**: Không cho phép ký tự đặc biệt, spaces, hoặc payload XSS
- **Whitelist approach**: Chỉ cho phép characters an toàn

---

## 6️⃣ user_manage.php - QUẢN LÝ USER

### ✅ FIX #16: Authorization Check - Không Cho Phép Role Injection (Dòng 14-17)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Role được lấy từ GET parameter trước session
$userRole = isset($_GET['role']) ? $_GET['role'] : (isset($_SESSION['role']) ? $_SESSION['role'] : 'user');

if (!isset($_SESSION['username']) || $userRole !== 'admin') {
    header('Location: index.php');
    exit();
}
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 14-17: Chỉ check role từ session, không tin tưởng GET parameter
if (!isset($_SESSION['username']) || $_SESSION['role'] !== 'admin') {
    header('Location: index.php');
    exit();
}
\`\`\`

**Giải thích:**
- **Chỉ tin tưởng session**: Không lấy role từ GET parameter `$_GET['role']`
- **Trực tiếp check `$_SESSION['role']`**: So sánh với 'admin' từ session data đã được authenticate
- **Ngăn chặn Authorization Bypass**: User thường không thể truy cập admin panel bằng `?role=admin`

---

## 7️⃣ edit_post.php - SỬA BÀI VIẾT

### ✅ FIX #17: Authorization Check - Verify Ownership (Dòng 13-20, 36-45)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Không kiểm tra ownership
$stmt = $config->prepare("SELECT posts.* FROM posts WHERE posts.id = ?");
// ... lấy post
// Không có check: if ($post['user_id'] != current_user_id) { deny }
$stmt = $config->prepare("UPDATE posts SET content = ? WHERE id = ?"); // Update trực tiếp
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 13-20: Thêm CSRF validation
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}
$csrf = $_POST['csrf'] ?? '';
if (!hash_equals($_SESSION['csrf'], $csrf)) {
    $_SESSION['error'] = 'CSRF token không hợp lệ';
    header("Location: home.php");
    exit();
}

// Dòng 36-45: Kiểm tra ownership - chỉ owner hoặc admin được sửa
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
\`\`\`

**Giải thích:**
- **CSRF protection**: Validate CSRF token trước khi xử lý
- **Ownership check**: So sánh `post['user_id']` với `current_user_id`
- **Admin bypass**: Admin được phép sửa mọi bài viết
- **Ngăn chặn**: User1 không thể sửa bài viết của User2 hoặc Admin

---

## 8️⃣ delete_post.php - XÓA BÀI VIẾT

### ✅ FIX #18: POST Method Only - Từ Chối GET (Dòng 18-21)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Cho phép xóa qua GET method
if ($_SERVER['REQUEST_METHOD'] === 'GET'){
    $stmt = $config->prepare("DELETE FROM posts WHERE id = ?");
    // ... xóa post
}
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 18-21: Chỉ chấp nhận POST method
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header("Location: home.php");
    exit();
}
\`\`\`

**Giải thích:**
- **Reject non-POST methods**: GET, PUT, DELETE đều bị từ chối
- **Ngăn chặn GET-based CSRF**: Không thể xóa post qua link `<img src="delete_post.php?id=1">`

---

### ✅ FIX #19: Authorization Check - Verify Ownership Before Delete (Dòng 48-57)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Xóa trực tiếp không check ownership
$stmt = $config->prepare("DELETE FROM posts WHERE id = ?");
$stmt->bind_param("i", $post_id);
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 48-57: Kiểm tra ownership trước khi xóa
function getUserId($username, $config) {
    // ... helper function
}

$is_owner = ($post['user_id'] == getUserId($_SESSION['username'], $config));
$is_admin = (isset($_SESSION['role']) && $_SESSION['role'] === 'admin');

if (!$is_owner && !$is_admin) {
    $_SESSION['error'] = "Bạn không có quyền xóa bài viết này!";
    header("Location: home.php");
    exit();
}

// Xóa post sau khi đã verify
$stmt = $config->prepare("DELETE FROM posts WHERE id = ?");
\`\`\`

**Giải thích:**
- **Ownership verification**: Check `post['user_id']` với `current_user_id`
- **Admin privilege**: Admin được phép xóa mọi bài viết
- **Ngăn chặn**: User không thể xóa bài viết của người khác

---

### ✅ FIX #20: CSRF Protection + Input Validation (Dòng 23-36)

**Code đã fix:**
\`\`\`php
// Dòng 23-28: CSRF validation
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}
$csrf = $_POST['csrf'] ?? '';
if (!hash_equals($_SESSION['csrf'], $csrf)) {
    $_SESSION['error'] = 'CSRF token không hợp lệ';
    header("Location: home.php");
    exit();
}

// Dòng 30-36: Validate input từ POST
$post_id = isset($_POST['id']) ? (int)$_POST['id'] : 0;
if ($post_id <= 0) {
    $_SESSION['error'] = "ID bài viết không hợp lệ!";
    header("Location: home.php");
    exit();
}
\`\`\`

**Giải thích:**
- **CSRF token**: Validate token trước khi xóa
- **Type casting**: `(int)$_POST['id']` để đảm bảo là integer
- **Range check**: `$post_id <= 0` để reject invalid IDs

---

## 9️⃣ loadImage.php - LOAD ẢNH

### ✅ FIX #21: Path Traversal Prevention - realpath() và Validation (Dòng 3-21)

**Code vulnerable (mini_social):**
\`\`\`php
// VULNERABLE: Nối trực tiếp filename vào path
$baseDir = __DIR__ . "/uploads/" .DIRECTORY_SEPARATOR;
$filename = $_GET['filename'] ?? '';
$path = $baseDir . $filename; // Nguy hiểm!

if (file_exists($path)) {
    // ... readfile
}
\`\`\`

**Code đã fix (mini_social-fix):**
\`\`\`php
// Dòng 3-21: Sử dụng realpath() và validate path
$baseDir = realpath(__DIR__ . "/uploads/");
$filename = $_GET['filename'] ?? '';

// Kiểm tra filename có hợp lệ không
if (empty($filename)) {
    header("HTTP/1.1 400 Bad Request");
    exit('No filename provided');
}

// Resolve full path
$path = realpath($baseDir . DIRECTORY_SEPARATOR . $filename);

// Kiểm tra path có nằm trong baseDir không
if ($path === false || strpos($path, $baseDir) !== 0) {
    header("HTTP/1.1 400 Bad Request");
    exit('Invalid file path');
}

// Kiểm tra file có tồn tại không
if (!file_exists($path)) {
    header("HTTP/1.1 404 Not Found");
    exit('File not found');
}
\`\`\`

**Giải thích:**
- **realpath()**: Resolve absolute path và loại bỏ `..`, `.`, symbolic links
- **strpos($path, $baseDir) !== 0**: Đảm bảo file nằm trong thư mục `uploads/`
- **3-layer validation**: Check empty → check path valid → check file exists
- **Ngăn chặn Path Traversal**: 
  - `../config.php` → realpath resolve thành `/path/to/config.php` → không bắt đầu với `/path/to/uploads/` → reject
  - `../../etc/passwd` → tương tự reject

---

### ✅ FIX #22: MIME Type Validation - Whitelist (Dòng 23-30)

**Code đã fix:**
\`\`\`php
// Dòng 23-30: Validate và set MIME type an toàn
$ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
$mime = 'application/octet-stream';

if ($ext === 'png') { $mime = 'image/png'; }
elseif ($ext === 'jpg' || $ext === 'jpeg') { $mime = 'image/jpeg'; }
elseif ($ext === 'gif') { $mime = 'image/gif'; }
elseif ($ext === 'webp') { $mime = 'image/webp'; }
elseif ($ext === 'svg') { $mime = 'image/svg+xml'; }
else { $mime = 'text/plain; charset=utf-8'; }

header('Content-Type: ' . $mime);
readfile($path);
\`\`\`

**Giải thích:**
- **Extension whitelist**: Chỉ chấp nhận các image formats phổ biến
- **Default to text/plain**: Nếu không phải image, serve dưới dạng text (không execute)
- **Prevent MIME confusion**: Browser không thể đoán MIME type sai → không execute malicious files

---






**© 2025 Mini Social - Educational Security Project**