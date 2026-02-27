<?php
$host = 'localhost';
$db_name = 'skycastvs_db';
$username = 'root';
$password = '';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db_name", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch(PDOException $e) {
    header('HTTP/1.1 500 Internal Server Error');
    echo json_encode(['error' => 'Connection failed: ' . $e->getMessage()]);
    exit;
}
?>
