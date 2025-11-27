<?php
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://code.jquery.com https://cdnjs.cloudflare.com 'unsafe-inline'; style-src 'self' https://cdnjs.cloudflare.com 'unsafe-inline'; font-src 'self' https://cdnjs.cloudflare.com data:; img-src 'self' data:;");
header('X-XSS-Protection: 1; mode=block');
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');

ini_set('session.cookie_samesite', 'lax');
ini_set('session.cookie_secure', '1');
ini_set('session.cookie_httponly', '1');

session_start();
require_once 'config.php';

$filterUser = isset($_GET['username']) ? trim($_GET['username']) : '';

$rows = [];
if ($filterUser !== '') {
    if ($stmt = $config->prepare("SELECT id, username, email, subject, body, otp_code, created_at FROM emails WHERE username = ? ORDER BY created_at DESC, id DESC LIMIT 100")) {
        $stmt->bind_param("s", $filterUser);
        $stmt->execute();
        $res = $stmt->get_result();
        while ($r = $res->fetch_assoc()) { $rows[] = $r; }
        $stmt->close();
    }
} else {
    $q = $config->query("SELECT id, username, email, subject, body, otp_code, created_at FROM emails ORDER BY created_at DESC, id DESC LIMIT 100");
    if ($q) { while ($r = $q->fetch_assoc()) { $rows[] = $r; } }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Client (Test OTP)</title>
    <link rel="stylesheet" href="styles.css">
    <style>
        body { font-family: Arial, sans-serif; padding: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background: #f4f4f4; }
        code { background: #f7f7f7; padding: 2px 4px; }
    </style>
</head>
<body>
    <h2>Email giả lập — OTP xác thực</h2>
    <form method="get" style="margin-bottom:10px;">
        <input type="text" name="username" placeholder="Lọc theo username" value="<?php echo htmlspecialchars($filterUser, ENT_QUOTES, 'UTF-8'); ?>">
        <button type="submit">Lọc</button>
        <a href="client_email.php" style="margin-left:10px;">Bỏ lọc</a>
    </form>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>OTP</th>
                <th>Subject</th>
                <th>Body</th>
                <th>Thời gian</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($rows as $row): ?>
            <tr>
                <td><?php echo (int)$row['id']; ?></td>
                <td><?php echo htmlspecialchars($row['username'], ENT_QUOTES, 'UTF-8'); ?></td>
                <td><?php echo htmlspecialchars($row['email'], ENT_QUOTES, 'UTF-8'); ?></td>
                <td><code><?php echo htmlspecialchars($row['otp_code'], ENT_QUOTES, 'UTF-8'); ?></code></td>
                <td><?php echo htmlspecialchars($row['subject'], ENT_QUOTES, 'UTF-8'); ?></td>
                <td><?php echo htmlspecialchars($row['body'], ENT_QUOTES, 'UTF-8'); ?></td>
                <td><?php echo htmlspecialchars($row['created_at'], ENT_QUOTES, 'UTF-8'); ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</body>
</html>


