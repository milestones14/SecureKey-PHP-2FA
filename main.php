<?php
function generateSecret($length = 16) {
    $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // Base32 characters
    $secret = '';
    for ($i = 0; $i < $length; $i++) {
        $secret .= $characters[rand(0, strlen($characters) - 1)];
    }
    return $secret;
}

function getTimestamp() {
    return floor(microtime(true) / 30);
}

function base32Decode($b32) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32 = strtoupper($b32); // Ensure uppercase
    $decoded = '';
    foreach (str_split($b32) as $char) {
        $decoded .= str_pad(base_convert(strpos($alphabet, $char), 10, 2), 5, '0', STR_PAD_LEFT);
    }
    $binaryData = '';
    foreach (str_split($decoded, 8) as $binary) {
        $binaryData .= chr(bindec($binary));
    }
    return $binaryData;
}

function generateTotp($secret, $digits = 6) {
    $timestamp = getTimestamp();
    $secret = base32Decode($secret);
    $hmac = hash_hmac('sha1', pack('N*', 0) . pack('N*', $timestamp), $secret, true);
    $offset = ord($hmac[strlen($hmac) - 1]) & 0xF;
    $code = (ord($hmac[$offset]) & 0x7F) << 24 |
            (ord($hmac[$offset + 1]) & 0xFF) << 16 |
            (ord($hmac[$offset + 2]) & 0xFF) << 8 |
            (ord($hmac[$offset + 3]) & 0xFF);
    return str_pad($code % pow(10, $digits), $digits, '0', STR_PAD_LEFT);
}

function verifyTotp($secret, $userCode, $window = 1, $digits = 6) {
    for ($i = -$window; $i <= $window; $i++) {
        $timestamp = getTimestamp() + $i;
        if (generateTotp($secret, $digits) === $userCode) {
            return true;
        }
    }
    return false;
}
?>
