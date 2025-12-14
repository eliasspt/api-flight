<?php
  require 'vendor/autoload.php';

  $usuarios = new classes\usuarios;

  header('Content-Type: application/json; charset=utf-8');
  header('Access-Control-Allow-Origin: *');
  header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
  header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

  Flight::route('POST /auth', [$usuarios, 'auth']);
  Flight::route('POST /usuarios', [$usuarios, 'crear']);
  Flight::route('GET /usuarios', [$usuarios, 'listarTodos']);
  Flight::route('GET /usuarios/@id', [$usuarios, 'listarUno']);
  Flight::route('PUT /usuarios/@id', [$usuarios, 'editar']);
  Flight::route('DELETE /usuarios/@id', [$usuarios, 'borrar']);

  Flight::map('error', function (Throwable $ex) {
    Flight::json(['status' => 'error', 'message' => $ex->getMessage()], 500);
  });

  Flight::start();
?>