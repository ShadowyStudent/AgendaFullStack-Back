<?php
require_once __DIR__ . '/../_cors.php';
header('Content-Type: application/json; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

$dbPath = __DIR__ . '/../../config/db.php';
$jwtPath = __DIR__ . '/../../config/jwt.php';
if (!file_exists($dbPath) || !file_exists($jwtPath)) {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Configuración no encontrada']);
    exit;
}
require_once $dbPath;
require_once $jwtPath;

function safe_log($text, $context = '') {
    $dir = __DIR__ . '/../../logs';
    if (!is_dir($dir)) mkdir($dir, 0770, true);
    $safeContext = is_string($context) ? preg_replace('/("password"\s*:\s*)"([^"]*)"/i', '$1"[FILTERED]"', $context) : '';
    $entry = date('c') . ' ' . $text . ($safeContext !== '' ? ' | ' . substr($safeContext, 0, 1000) : '') . PHP_EOL;
    file_put_contents($dir . '/error.log', $entry, FILE_APPEND);
}

$headers = function_exists('getallheaders') ? getallheaders() : [];
$auth = $headers['Authorization'] ?? $headers['authorization'] ?? $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (empty($auth) && !empty($_COOKIE['agenda_token'])) {
    $auth = 'Bearer ' . trim($_COOKIE['agenda_token']);
}
if (!$auth || !preg_match('/Bearer\s(\S+)/', (string)$auth, $m)) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Token missing']);
    exit;
}
$token = $m[1];

$env = [];
$envFile = __DIR__ . '/../../.env';
if (file_exists($envFile)) $env = parse_ini_file($envFile) ?: [];
$secret = $env['JWT_SECRET'] ?? getenv('JWT_SECRET') ?? '';
if ($secret === '') {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Server configuration error']);
    exit;
}

$payload = jwt_validate($token, $secret);
if (!$payload) {
    try {
        $stmt = $pdo->prepare('SELECT id FROM usuarios WHERE token = ? LIMIT 1');
        $stmt->execute([$token]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user && !empty($user['id'])) {
            $payload = ['sub' => $user['id']];
        } else {
            http_response_code(401);
            echo json_encode(['success' => false, 'message' => 'Invalid token']);
            exit;
        }
    } catch (Throwable $e) {
        safe_log('Token fallback error', $e->getMessage());
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Error interno del servidor']);
        exit;
    }
}

$usuario_id = isset($payload['sub']) ? (int)$payload['sub'] : 0;
if ($usuario_id <= 0) {
    http_response_code(401);
    echo json_encode(['success' => false, 'message' => 'Invalid token payload']);
    exit;
}

$input = $_POST;
$raw = file_get_contents('php://input');
if ((empty($input) || count($input) === 0) && $raw) {
    $json = json_decode($raw, true);
    if (is_array($json)) $input = $json;
}

$id = intval($input['id'] ?? 0);
if ($id <= 0) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'ID inválido']);
    exit;
}

$nombre = trim((string)($input['nombre'] ?? ''));
$apellido = trim((string)($input['apellido'] ?? ''));
$telefono = trim((string)($input['telefono'] ?? ''));
$email = trim((string)($input['email'] ?? ''));
$direccion = trim((string)($input['direccion'] ?? ''));
$notas = trim((string)($input['notas'] ?? ''));

if ($nombre === '' || $telefono === '') {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Nombre y teléfono son obligatorios']);
    exit;
}
if (mb_strlen($nombre) > 100 || mb_strlen($apellido) > 100 || mb_strlen($telefono) > 20 || mb_strlen($email) > 120 || mb_strlen($direccion) > 255) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Campos demasiado largos']);
    exit;
}
if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Email inválido']);
    exit;
}

$uploadsRoot = realpath(__DIR__ . '/../../uploads') ?: (__DIR__ . '/../../uploads');
$contactosDir = $uploadsRoot . '/contactos';
if (!is_dir($contactosDir)) {
    if (!mkdir($contactosDir, 0755, true) && !is_dir($contactosDir)) {
        safe_log('mkdir failed: ' . $contactosDir);
        http_response_code(500);
        echo json_encode(['success' => false, 'message' => 'Error interno del servidor']);
        exit;
    }
}
$contactosDirReal = realpath($contactosDir) ?: $contactosDir;

try {
    $pdo->beginTransaction();

    $stmt = $pdo->prepare('SELECT foto FROM contactos WHERE id = ? AND usuario_id = ? LIMIT 1');
    $stmt->execute([$id, $usuario_id]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) {
        $pdo->rollBack();
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Contacto no encontrado']);
        exit;
    }

    $newFotoName = null;
    if (!empty($_FILES['foto']) && isset($_FILES['foto']['error']) && $_FILES['foto']['error'] === UPLOAD_ERR_OK && is_uploaded_file($_FILES['foto']['tmp_name'])) {
        if ($_FILES['foto']['size'] > 2 * 1024 * 1024) {
            $pdo->rollBack();
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Imagen demasiado grande (máx 2MB)']);
            exit;
        }

        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = $finfo ? finfo_file($finfo, $_FILES['foto']['tmp_name']) : ($_FILES['foto']['type'] ?? '');
        if ($finfo) finfo_close($finfo);
        $allowedMime = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
        if (!in_array($mime, $allowedMime, true)) {
            $pdo->rollBack();
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Tipo de archivo no permitido']);
            exit;
        }

        $ext = strtolower(pathinfo($_FILES['foto']['name'] ?? '', PATHINFO_EXTENSION));
        $allowedExt = ['jpg','jpeg','png','webp','gif'];
        if (!in_array($ext, $allowedExt, true)) {
            $pdo->rollBack();
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Formato de imagen no permitido']);
            exit;
        }

        try {
            $newFotoName = 'c_' . bin2hex(random_bytes(8)) . '.' . $ext;
        } catch (Throwable $e) {
            safe_log('random_bytes failed', $e->getMessage());
            $pdo->rollBack();
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Error interno al procesar la imagen']);
            exit;
        }

        $dest = $contactosDirReal . '/' . basename($newFotoName);
        if (!move_uploaded_file($_FILES['foto']['tmp_name'], $dest)) {
            safe_log('move_uploaded_file failed', json_encode(['tmp' => $_FILES['foto']['tmp_name'], 'dest' => $dest]));
            $pdo->rollBack();
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Error al guardar la imagen']);
            exit;
        }

        $realDest = realpath($dest);
        if ($realDest === false || strpos($realDest, $contactosDirReal) !== 0) {
            @unlink($dest);
            safe_log('Uploaded file outside destination dir', $dest);
            $pdo->rollBack();
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Error al guardar la imagen']);
            exit;
        }
        @chmod($realDest, 0640);

        if (!empty($row['foto'])) {
            $oldName = basename($row['foto']);
            $oldPath = $contactosDirReal . '/' . $oldName;
            $oldReal = realpath($oldPath);
            if ($oldReal !== false && strpos($oldReal, $contactosDirReal) === 0 && is_file($oldReal)) {
                try { unlink($oldReal); } catch (Throwable $e) { safe_log('unlink old foto failed', $e->getMessage()); }
            }
        }
    }

    $sql = 'UPDATE contactos SET nombre = ?, apellido = ?, telefono = ?, email = ?, direccion = ?, notas = ?';
    $params = [
        $nombre,
        $apellido !== '' ? $apellido : null,
        $telefono !== '' ? $telefono : null,
        $email !== '' ? $email : null,
        $direccion !== '' ? $direccion : null,
        $notas !== '' ? $notas : null
    ];
    if ($newFotoName !== null) {
        $sql .= ', foto = ?';
        $params[] = $newFotoName;
    }
    $sql .= ' WHERE id = ? AND usuario_id = ?';
    $params[] = $id;
    $params[] = $usuario_id;

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    if ($stmt->rowCount() === 0) {
        $pdo->commit();
        http_response_code(404);
        echo json_encode(['success' => false, 'message' => 'Contacto no encontrado o no autorizado']);
        exit;
    }

    $stmt = $pdo->prepare('SELECT id, nombre, apellido, telefono, email, direccion, notas, foto FROM contactos WHERE id = ? AND usuario_id = ? LIMIT 1');
    $stmt->execute([$id, $usuario_id]);
    $updated = $stmt->fetch(PDO::FETCH_ASSOC);
    $pdo->commit();

    if (!$updated) {
        echo json_encode(['success' => true]);
        exit;
    }

    $fotoUrl = null;
    if (!empty($updated['foto'])) {
        $fotoVal = $updated['foto'];
        if (preg_match('#^https?://#i', $fotoVal)) {
            $fotoUrl = $fotoVal;
        } else {
            $base = rtrim($env['BASE_URL'] ?? getenv('BASE_URL'), '/');
            $fotoUrl = $base . '/backend/uploads/contactos/' . rawurlencode(basename($fotoVal));
        }
    }
    $updated['foto'] = $fotoUrl;

    echo json_encode(['success' => true, 'data' => $updated]);
    exit;
} catch (Throwable $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        try { $pdo->rollBack(); } catch (Throwable $_) {}
    }
    safe_log('update contacto error', $e->getMessage());
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Error interno del servidor']);
    exit;
}