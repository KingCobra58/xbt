<?php
require_once __DIR__ . '/xbt_config.php';

/** @var mysqli|null $db */
$db = null;

function db_connect()
{
    global $mysql, $db;

    if ($db instanceof mysqli) {
        return $db;
    }

    // Keep legacy error handling predictable across PHP 7.4 through 8.5+.
    mysqli_report(MYSQLI_REPORT_OFF);

    $host = isset($mysql['host']) ? (string) $mysql['host'] : 'localhost';
    $user = isset($mysql['user']) ? (string) $mysql['user'] : '';
    $password = isset($mysql['password']) ? (string) $mysql['password'] : '';
    $database = isset($mysql['db']) ? (string) $mysql['db'] : '';
    $port = isset($mysql['port']) ? (int) $mysql['port'] : 3306;

    $db = mysqli_init();
    if (!$db) {
        die('Unable to initialize the MySQL connection.');
    }

    if (!@mysqli_real_connect($db, $host, $user, $password, $database, $port)) {
        die(htmlspecialchars(mysqli_connect_error(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'));
    }

    // utf8mb4 works with modern MySQL/MariaDB and is safe for these helper pages.
    @mysqli_set_charset($db, 'utf8mb4');

    return $db;
}

function db_query($query)
{
    $db = db_connect();
    $result = mysqli_query($db, $query);

    if ($result === false) {
        die(sprintf(
            '%s<br>%s',
            htmlspecialchars(mysqli_error($db), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
            htmlspecialchars($query, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
        ));
    }

    return $result;
}

function db_query_first($query)
{
    $result = db_query($query);
    $row = mysqli_fetch_assoc($result);
    mysqli_free_result($result);

    return $row ?: array();
}

function db_query_first_field($query)
{
    $result = db_query($query);
    $row = mysqli_fetch_row($result);
    mysqli_free_result($result);

    return $row !== null && array_key_exists(0, $row) ? $row[0] : null;
}

function db_fetch_assoc($result)
{
    return mysqli_fetch_assoc($result);
}

db_connect();
