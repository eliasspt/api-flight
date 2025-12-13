<?php
	require 'vendor/autoload.php';

	use Firebase\JWT\JWT;
	use Firebase\JWT\Key;

	$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
	$dotenv->load();

	header('Content-Type: application/json; charset=utf-8');
	header('Access-Control-Allow-Origin: *');
	header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE');
	header('Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With');

	date_default_timezone_set('America/Caracas');

	function secretKey() {
		return hash('sha512', $_ENV['SECRET_KEY_APP']);
	}

	function getToken() {
		$headers = apache_request_headers();
		$token = explode(' ', $headers['authorization'])[1];
		try {
			return JWT::decode($token, new Key(secretKey(), 'HS256'));
		} catch (Exception $e) {
			Flight::halt(401, json_encode(['status' => 'error', 'message' => $e->getMessage()]));
		}
	}

	function checkToken() {
		$info = getToken();
		$db = Flight::db();
		$query = $db->prepare('SELECT * FROM usuarios WHERE id = :id');
		$query->execute([':id' => $info->data]);
		return $query->fetchColumn();
	}

	Flight::register(
		'db',
		'PDO',
		[
			"mysql:host={$_ENV['DB_HOST']};dbname={$_ENV['DB_NAME']};charset=utf8mb4",
			$_ENV['DB_USER'],
			$_ENV['DB_PASS'],
			[
				PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
				PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_OBJ,
				PDO::ATTR_EMULATE_PREPARES => false
			]
		]
	);

	Flight::route('POST /auth', 'auth');
	Flight::route('GET /usuarios', 'usuarios');
	Flight::route('GET /usuarios', 'usuario');
	Flight::route('POST /usuarios', 'crearUsuario');
	Flight::route('PUT /usuarios', 'editarUsuario');
	Flight::route('DELETE /usuarios', 'borrarUsuario');

	Flight::map('error', function (Throwable $ex) {
		Flight::json(['status'=> 'error','message'=> $ex->getMessage()]);
	});

	function auth() {
		$db = Flight::db();
		$correo = Flight::request()->data->correo;
		$contrasena = sha1(Flight::request()->data->contrasena);
		$query = $db->prepare('SELECT id FROM usuarios WHERE correo = :correo AND contrasena = :contrasena');

		if ($query->execute([':correo' => $correo, ':contrasena' => $contrasena])) {
			$data = $query->fetch();
			$payload = [
				'exp' => strtotime('now') + 3600,
				'data' => $data->id
			];
			$token = JWT::encode($payload, secretKey(), 'HS256');
			Flight::json(['token' => $token]);
		} else {
			Flight::json(['status' => 'error', 'message' => 'Credenciales incorrectas']);
		}
	}

	function usuarios() {
		if (!checkToken()) {
			Flight::halt(401, json_encode(['status' => 'error', 'message' => 'Unauthorized']));
		}
		$db = Flight::db();
		$query = $db->prepare('SELECT id, nombre, telefono, correo, actualizado, registrado FROM usuarios');
		$query->execute();
		$data = $query->fetchAll();
		Flight::json($data);
	}

	function usuario($id) {
		if (!checkToken()) {
			Flight::halt(401, json_encode(['status' => 'error', 'message' => 'Unauthorized']));
		}
		$db = Flight::db();
		if (!isset($id)) $id = Flight::request()->data->id;
		$query = $db->prepare('SELECT id, nombre, telefono, correo, actualizado, registrado FROM usuarios WHERE id = :id');
		$query->execute([':id' => $id]);
		$data = $query->fetch();
		Flight::json($data);
	}

	function crearUsuario() {
		if (!checkToken()) {
			Flight::halt(401, json_encode(['status' => 'error', 'message' => 'Unauthorized']));
		}
		$db = Flight::db();
		$nombre = Flight::request()->data->nombre;
		$telefono = Flight::request()->data->telefono;
		$correo = Flight::request()->data->correo;
		$contrasena = sha1(Flight::request()->data->contrasena);
		$query = $db->prepare('INSERT INTO usuarios (nombre, telefono, correo, contrasena) VALUES (:nombre, :telefono, :correo, :contrasena)');
		if ($query->execute([':nombre' => $nombre,':telefono' => $telefono,':correo' => $correo,':contrasena' => $contrasena])) {
			usuario($db->lastInsertId());
		} else {
			Flight::json(['status'=> 'error', 'message'=> $query->errorInfo()]);
		}
	}

	function editarUsuario()	{
		if (!checkToken()) {
			Flight::halt(401, json_encode(['status' => 'error', 'message' => 'Unauthorized']));
		}
		$db = Flight::db();
		$id = Flight::request()->data->id;
		$nombre = Flight::request()->data->nombre;
		$telefono = Flight::request()->data->telefono;
		$correo = Flight::request()->data->correo;
		$query = $db->prepare('UPDATE usuarios SET nombre = :nombre, telefono = :telefono, correo = :correo WHERE id = :id');
		if ($query->execute([':id' => $id, ':nombre' => $nombre, ':telefono' => $telefono, ':correo' => $correo])) {
			usuario($id);
		} else {
			Flight::json(['status' => 'error', 'message' => $query->errorInfo()]);
		}
	}

	function borrarUsuario() {
		if (!checkToken()) {
			Flight::halt(401, json_encode(['status' => 'error', 'message' => 'Unauthorized']));
		}
		$db = Flight::db();
		$id = Flight::request()->data->id;
		$query = $db->prepare('DELETE FROM usuarios WHERE id = :id');
		if ($query->execute([':id' => $id])) {
			Flight::json(['status' => 'success', 'message' => 'El usuario ha sido eliminado']);
		} else {
			Flight::json(['status' => 'error', 'message' => $query->errorInfo()]);
		}
	}

	Flight::start();
?>