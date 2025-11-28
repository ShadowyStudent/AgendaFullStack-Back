<?php
$dotenv = parse_ini_file(__DIR__ . '/../.env') ?: [];
$host = $dotenv['DB_HOST'] ?? getenv('DB_HOST') ?: null;
$port = $dotenv['DB_PORT'] ?? getenv('DB_PORT') ?: null;
$db   = $dotenv['DB_NAME'] ?? getenv('DB_NAME') ?: null;
$user = $dotenv['DB_USER'] ?? getenv('DB_USER') ?: null;
$pass = $dotenv['DB_PASS'] ?? getenv('DB_PASS') ?: null;

if (!$host || !$db || !$user) {
    throw new Exception('Variables de entorno DB incompletas');
}

$port = is_numeric($port) ? (int)$port : null;
$portPart = $port ? ";port={$port}" : '';
$dsn = "mysql:host={$host}{$portPart};dbname={$db};charset=utf8mb4";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (PDOException $e) {
    $dir = __DIR__ . '/../../logs';
    if (!is_dir($dir)) {
        mkdir($dir, 0770, true);
    }
    $logMessage = date('c') . " DB connection error: " . $e->getMessage() . PHP_EOL;
    file_put_contents($dir . '/error.log', $logMessage, FILE_APPEND);
    throw new Exception('DB connection error');
}