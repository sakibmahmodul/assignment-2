<?php
session_start();
require_once 'controller/AuthController.php';

$auth = new AuthController();
$auth->logout();
?>