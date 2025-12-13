<?php
  /**
   * API REST de Gestión de Usuarios
   * Desarrollada con FlightPHP, JWT y PDO.
   */

  require 'vendor/autoload.php';

  // Configuración de margen de tiempo (60s) para validación de tokens JWT
  // Evita errores si el reloj del servidor y el cliente no están perfectamente sincronizados.
  Firebase\JWT\JWT::$leeway = 60;
  
  use Firebase\JWT\JWT;
  use Firebase\JWT\Key;

  // Carga de variables de entorno desde el archivo .env
  $dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
  $dotenv->load();

  /**
   * CONFIGURACIÓN DE CABECERAS (CORS)
   * Permite que aplicaciones externas (como React, Vue o Mobile) consuman la API.
   */
  header('Content-Type: application/json; charset=utf-8');
  header('Access-Control-Allow-Origin: *');
  header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
  header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

  // Ajuste de zona horaria según la ubicación del servidor
  date_default_timezone_set('America/Caracas');

  // --- HELPERS DE SEGURIDAD Y VALIDACIÓN ---

  /**
   * Verifica si el usuario actual tiene permiso para acceder a un recurso específico.
   * @param int $idRequerido El ID del usuario al que se intenta acceder/modificar.
   * @return object Datos decodificados del token.
   */
  function verificarPermiso($idRequerido) {
    $usuario = getTokenData();
    // Un usuario solo puede acceder si es administrador O si es el dueño de la cuenta
    if ($usuario->rol !== 'admin' && $usuario->id != $idRequerido) {
      Flight::halt(403, json_encode([
        'status' => 'error',
        'message' => 'No tienes permisos para realizar esta acción'
      ]));
    }
    return $usuario;
  }

  /**
   * Extrae y valida el token JWT enviado en los headers.
   * @return object Datos del payload (id, rol).
   */
  function getTokenData() {
    $headers = array_change_key_case(getallheaders(), CASE_LOWER);
    if (!isset($headers['authorization'])) {
      Flight::halt(401, json_encode(['status' => 'error', 'message' => 'Token no proporcionado']));
    }

    $authHeader = $headers['authorization'];
    $token = str_replace('Bearer ', '', $authHeader);

    try {
      // Decodificación del token usando la clave secreta definida en .env
      $decoded = JWT::decode($token, new Key($_ENV['SECRET_KEY_APP'], 'HS256'));
      return $decoded->data;
    } catch (Exception $e) {
      Flight::halt(401, json_encode(['status' => 'error', 'message' => 'Token inválido: ' . $e->getMessage()]));
    }
  }

  /**
   * Retorna la cantidad total de registros en la tabla usuarios.
   */
  function totalUsuarios() {
    $db = Flight::db();
    $query = $db->query('SELECT COUNT(id) FROM usuarios');
    return $query->fetchColumn();
  }

  /**
   * Verifica la existencia de un usuario por su ID.
   */
  function existeUsuario($id) {
    $db = Flight::db();
    $query = $db->prepare('SELECT id FROM usuarios WHERE id = ?');
    $query->execute([$id]);
    return $query->fetch();
  }

  /**
   * Verifica si un correo ya está registrado, permitiendo excluir un ID (útil en ediciones).
   */
  function existeCorreo($correo, $id = 0) {
    $db = Flight::db();
    if ($id === 0) {
      $query = $db->prepare('SELECT id FROM usuarios WHERE correo = ?');
      $query->execute([$correo]);
    } else {
      $query = $db->prepare('SELECT id FROM usuarios WHERE correo = ? AND id != ?');
      $query->execute([$correo, $id]);
    }
    return $query->fetch();
  }

  // --- REGISTRO DE COMPONENTES ---

  // Registro de la conexión PDO en el motor de Flight
  Flight::register('db', 'PDO', [
    "mysql:host={$_ENV['DB_HOST']};dbname={$_ENV['DB_NAME']};charset=utf8mb4",
    $_ENV['DB_USER'],
    $_ENV['DB_PASS'],
    [
      PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
      PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_OBJ,
      PDO::ATTR_EMULATE_PREPARES => false // Desactiva la emulación para mayor seguridad contra SQL Injection
    ]
  ]);

  // --- DEFINICIÓN DE RUTAS ---

  Flight::route('POST /auth', 'auth'); // Login
  Flight::route('GET /usuarios', 'listarUsuarios'); // Ver todos (Solo Admin)
  Flight::route('GET /usuarios/@id', 'obtenerUsuario'); // Ver uno (Dueño o Admin)
  Flight::route('POST /usuarios', 'crearUsuario'); // Registro (Lógica de primer admin)
  Flight::route('PUT /usuarios/@id', 'editarUsuario'); // Actualizar (Lógica de campos protegidos)
  Flight::route('DELETE /usuarios/@id', 'borrarUsuario'); // Eliminar (Protección de cuenta propia)

  // Manejador global de errores (Captura excepciones no controladas)
  Flight::map('error', function (Throwable $ex) {
    Flight::json(['status' => 'error', 'message' => $ex->getMessage()], 500);
  });

  // --- CONTROLADORES ---

  /**
   * Autenticación de usuarios y generación de JWT.
   */
  function auth() {
    $db = Flight::db();
    $data = Flight::request()->data;
    
    $query = $db->prepare('SELECT id, contrasena, rol FROM usuarios WHERE correo = ?');
    $query->execute([$data->correo]);
    $user = $query->fetch();

    // Verificación de hash de contraseña
    if ($user && password_verify($data->contrasena, $user->contrasena)) {
      $now = time();
      $payload = [
        'iat' => $now,
        'nbf' => $now,
        'exp' => $now + 3600, // Expira en 1 hora
        'data' => [
          'id' => $user->id,
          'rol' => $user->rol
        ]
      ];
      $token = JWT::encode($payload, $_ENV['SECRET_KEY_APP'], 'HS256');
      Flight::json(['status' => 'success', 'token' => $token]);
    } else {
      Flight::halt(401, json_encode(['status' => 'error', 'message' => 'Credenciales incorrectas']));
    }
  }

  /**
   * Crea un nuevo usuario.
   * Lógica: El primer registro siempre es admin.
	 * Los siguientes requieren token admin si se desea asignar roles, de lo contrario son 'user'.
   */
  function crearUsuario() {
    $db = Flight::db();
    $req = Flight::request()->data;
    
    if (totalUsuarios()) {
      // Si ya hay usuarios, verificamos quién está intentando crear este nuevo registro
      $usuarioLogueado = getTokenData();
      if ($usuarioLogueado->rol === 'admin') {
        $rol = (isset($req->rol) && in_array($req->rol, ['admin', 'user'])) ? $req->rol : 'user';
      } else {
        $rol = 'user'; // Usuarios normales solo pueden crear otros 'user'
      }
    } else {
      $rol = 'admin'; // El primer usuario de la historia de la DB es el administrador
    }

    // Validaciones de seguridad
    if (strlen($req->contrasena) < 4 || strlen($req->contrasena) > 72) {
      Flight::halt(400, json_encode(['status' => 'error', 'message' => 'La contraseña debe tener entre 4 y 72 caracteres']));
    }

    if (!filter_var($req->correo, FILTER_VALIDATE_EMAIL)) {
      Flight::halt(400, json_encode(['status' => 'error', 'message' => 'Correo electrónico no válido']));
    } elseif (existeCorreo($req->correo)) {
      Flight::halt(400, json_encode(['status' => 'error', 'message' => 'Correo electrónico ya registrado']));
    }

    $passHash = password_hash($req->contrasena, PASSWORD_BCRYPT);
    
    $query = $db->prepare('INSERT INTO usuarios (nombre, telefono, correo, contrasena, rol) VALUES (?, ?, ?, ?, ?)');
    $query->execute([$req->nombre, $req->telefono, $req->correo, $passHash, $rol]);
    
    obtenerUsuario($db->lastInsertId(), 201);
  }

  /**
   * Lista todos los usuarios
	 * Protege para que solo el admin lo vea
   */
  function listarUsuarios() {
    $usuarioLogueado = getTokenData();

    if ($usuarioLogueado->rol !== 'admin') {
      Flight::halt(403, json_encode(['status' => 'error', 'message' => 'Acceso denegado']));
    }
    
    $db = Flight::db();
    $query = $db->query('SELECT id, nombre, telefono, correo, actualizado, registrado FROM usuarios');
    Flight::json([
      'status' => 'success',
      'data' => $query->fetchAll()
    ]);
  }

  /**
   * Obtiene detalles de un usuario por ID.
	 * Protege para que solo el dueño o el admin lo vean
   */
  function obtenerUsuario($id, $status = 200) {
    verificarPermiso($id); // Protege para que solo el dueño o el admin lo vean
    $db = Flight::db();
    $query = $db->prepare('SELECT id, nombre, telefono, correo, actualizado, registrado FROM usuarios WHERE id = ?');
    $query->execute([$id]);
    $data = $query->fetch();
    
    if (!$data) {
      Flight::halt(404, json_encode(['status' => 'error', 'message' => 'Usuario no encontrado']));
    }

    Flight::json([
      'status' => 'success',
      'data' => $data
    ], $status);
  }

  /**
   * Edita campos de forma dinámica.
	 * Protege para que solo el dueño o el admin lo edite
   * Lógica: Los usuarios normales no pueden editar su propio 'rol'.
	 * Puede editar cualquier campo (todos o uno), excepto 'rol' si no es admin
   */
  function editarUsuario($id) {
    $usuarioLogueado = verificarPermiso($id);
    
    $db = Flight::db();
    $req = Flight::request()->data;

    if (!existeUsuario($id)) {
      Flight::halt(404, json_encode(['status' => 'error', 'message' => 'Usuario no encontrado']));
    }

    // Definición de campos que se pueden actualizar
    $camposDisponibles = ['nombre', 'telefono', 'correo', 'contrasena'];

    // Solo un admin puede ver/editar el campo rol en el UPDATE
    if ($usuarioLogueado->rol === 'admin') {
      $camposDisponibles[] = 'rol';
    }

    $sets = [];
    $params = [];

    foreach ($camposDisponibles as $campo) {
      if (isset($req->$campo) && $req->$campo !== '') {
        $valor = $req->$campo;

        switch ($campo) {
          case 'contrasena':
            if (strlen($valor) < 4 || strlen($valor) > 72) {
              Flight::halt(400, json_encode(['status' => 'error', 'message' => 'Contraseña inválida']));
            }
            $valor = password_hash($valor, PASSWORD_BCRYPT);
            break;
          case 'correo':
            if (!filter_var($valor, FILTER_VALIDATE_EMAIL)) {
              Flight::halt(400, json_encode(['status' => 'error', 'message' => 'Correo inválido']));
            } elseif (existeCorreo($valor, $id)) {
              Flight::halt(400, json_encode(['status' => 'error', 'message' => 'Correo en uso']));
            }
            break;
          case 'rol':
            // Protección: Un admin no puede quitarse el admin a sí mismo
            if ($usuarioLogueado->id == $id && $valor === 'user') {
              Flight::halt(400, json_encode(['status' => 'error', 'message' => 'No puedes quitarte el rango de administrador']));
            }
            if (!in_array($valor, ['admin', 'user'])) {
              Flight::halt(400, json_encode(['status' => 'error', 'message' => 'Rol no válido']));
            }
            break;
        }

        $sets[] = "$campo = ?";
        $params[] = $valor;
      }
    }

    if (empty($sets)) {
      Flight::halt(400, json_encode(['status' => 'error', 'message' => 'Nada que actualizar']));
    }

    $params[] = $id;
    $sql = "UPDATE usuarios SET " . implode(', ', $sets) . " WHERE id = ?";

    $query = $db->prepare($sql);
    if ($query->execute($params)) {
      obtenerUsuario($id);
    } else {
      Flight::halt(500, json_encode(['status' => 'error', 'message' => 'Error en la actualización']));
    }
  }

  /**
   * Elimina un usuario.
	 * Protección: Sólo puede borrarse a si mismo, a menos que sea un administrador.
	 * Protección: Un administrador no puede eliminarse a sí mismo.
   */
  function borrarUsuario($id) {
    $usuarioLogueado = verificarPermiso($id);

    if ($usuarioLogueado->id == $id && $usuarioLogueado->rol === 'admin') {
      Flight::halt(400, json_encode(['status' => 'error', 'message' => 'No puedes eliminar tu propia cuenta de administrador']));
    }
    
    if (!existeUsuario($id)) {
      Flight::halt(404, json_encode(['status' => 'error', 'message' => 'Usuario no encontrado']));
    }

    $db = Flight::db();
    $query = $db->prepare('DELETE FROM usuarios WHERE id = ?');
    $query->execute([$id]);
    Flight::json(['status' => 'success', 'message' => 'Usuario eliminado']);
  }

  // Inicio del motor Flight
  Flight::start();
?>