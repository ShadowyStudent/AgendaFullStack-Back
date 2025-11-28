<?php
header('Content-Type: application/json; charset=utf-8');

echo json_encode([
    'status' => 'ok',
    'message' => 'AgendaFullStack API online',
    'description' => 'API REST con autenticación JWT y CRUD de contactos asociados al usuario autenticado.',
    'endpoints' => [
        'POST /api/auth/login.php' => 'Autenticación con JWT',
        'POST /api/registrar.php' => 'Registrar nuevo usuario',
        'GET /api/perfil.php' => 'Obtener perfil del usuario autenticado',
        'GET /api/contactos/index.php' => 'Listar contactos',
        'POST /api/contactos/crear.php' => 'Crear contacto',
        'PUT /api/contactos/actualizar.php' => 'Actualizar contacto',
        'DELETE /api/contactos/eliminar.php' => 'Eliminar contacto'
    ]
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);