<?php
function base64url_decode($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) $data .= str_repeat('=', 4 - $remainder);
    $data = strtr($data, '-_', '+/');
    $decoded = base64_decode($data);
    return $decoded === false ? false : $decoded;
}

function jwt_validate($token, $secret = '') {
    if (empty($secret)) {
        $env = parse_ini_file(__DIR__ . '/../.env') ?: [];
        $secret = $env['JWT_SECRET'] ?? getenv('JWT_SECRET') ?: '';
    }

    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return false;
    }

    list($headb64, $bodyb64, $sigb64) = $parts;
    $headDecoded = base64url_decode($headb64);
    $bodyDecoded = base64url_decode($bodyb64);
    $sig = base64url_decode($sigb64);

    if ($headDecoded === false || $bodyDecoded === false || $sig === false) {
        return false;
    }

    $header = json_decode($headDecoded, true);
    $payload = json_decode($bodyDecoded, true);

    if (!is_array($header) || !is_array($payload)) {
        return false;
    }

    $alg = $header['alg'] ?? 'HS256';
    if ($alg !== 'HS256') {
        return false;
    }

    if ($secret === '') {
        return false;
    }

    $data = $headb64 . '.' . $bodyb64;
    $expected = hash_hmac('sha256', $data, $secret, true);

    if (!hash_equals($expected, $sig)) {
        return false;
    }

    $now = time();
    if (isset($payload['exp']) && $payload['exp'] < $now) {
        return false;
    }
    if (isset($payload['nbf']) && $payload['nbf'] > $now) {
        return false;
    }
    if (isset($payload['iat']) && $payload['iat'] > $now) {
        return false;
    }

    return $payload;
}

function jwt_decode_no_verify($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    $bodyb64 = $parts[1];
    $bodyDecoded = base64url_decode($bodyb64);
    if ($bodyDecoded === false) return null;
    return json_decode($bodyDecoded, true);
}