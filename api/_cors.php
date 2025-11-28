<?php
$whitelist = [
    'https://shadowystudent.github.io',
    'https://agendafullstack.unaux.com'
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $whitelist, true)) {
    header("Access-Control-Allow-Origin: $origin");
} else {
    header("Access-Control-Allow-Origin: https://shadowystudent.github.io");
}

header('Access-Control-Allow-Credentials: true');
header('Access-Control-Expose-Headers: Authorization, X-Total-Count');
header('Access-Control-Max-Age: 600');
header('Vary: Origin');
header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-Authorization, X-Auth-Token, Accept');
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}