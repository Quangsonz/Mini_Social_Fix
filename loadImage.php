<?php

$baseDir = realpath(__DIR__ . "/uploads/");
$filename = $_GET['filename'] ?? '';

// Kiểm tra filename có hợp lệ không
if (empty($filename)) {
    header("HTTP/1.1 400 Bad Request");
    exit('No filename provided');
}

$path = realpath($baseDir . DIRECTORY_SEPARATOR . $filename);

// Kiểm tra path có nằm trong thư mục uploads không
if ($path === false || strpos($path, $baseDir) !== 0) {
    header("HTTP/1.1 400 Bad Request");
    exit('Invalid file path');
}

// Kiểm tra file có tồn tại không
if (!file_exists($path)) {
    header("HTTP/1.1 404 Not Found");
    exit('File not found');
}

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