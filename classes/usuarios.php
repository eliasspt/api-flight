<?php
	namespace Classes;

	use Firebase\JWT\JWT;
	use Firebase\JWT\Key;
	use flight;
	use Dotenv\Dotenv;
	use PDO;
	use Exception;

	JWT::$leeway = 60;

	$dotenv = Dotenv::createImmutable(dirname(__DIR__));
	$dotenv->load();
  
  date_default_timezone_set('America/Caracas');

	class Usuarios {
		private $db;

		public function __construct() {
			Flight::register('db', 'PDO', [
				"mysql:host={$_ENV['DB_HOST']};port={$_ENV['DB_PORT']};dbname={$_ENV['DB_NAME']};charset=utf8mb4",
				$_ENV['DB_USER'],
				$_ENV['DB_PASS'],
				[
					PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
					PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_OBJ,
					PDO::ATTR_EMULATE_PREPARES => false
				]
			]);
			$this->db = Flight::db();
			$this->db->query("SET time_zone = '-04:00'");
		}
		
		function verificarPermiso($idRequerido) {
			$usuario = $this->getTokenData();
			if ($usuario->rol !== 'admin' && $usuario->id != $idRequerido) {
				Flight::halt(403, json_encode([
					'status' => 'error',
					'message' => 'No tienes permisos para realizar esta acción'
				]));
			}
			return $usuario;
		}
	
		function getTokenData() {
			$headers = array_change_key_case(getallheaders(), CASE_LOWER);
			if (!isset($headers['authorization'])) {
				Flight::halt(401, json_encode(['status' => 'error', 'message' => 'Token no proporcionado']));
			}
	
			$authHeader = $headers['authorization'];
			$token = str_replace('Bearer ', '', $authHeader);
	
			try {
				$decoded = JWT::decode($token, new Key($_ENV['SECRET_KEY_APP'], 'HS256'));
				return $decoded->data;
			} catch (Exception $e) {
				Flight::halt(401, json_encode(['status' => 'error', 'message' => 'Token inválido: ' . $e->getMessage()]));
			}
		}
	
		function totalUsuarios() {
			$query = $this->db->query('SELECT COUNT(id) FROM usuarios');
			return $query->fetchColumn();
		}
	
		function existeUsuario($id) {
			$query = $this->db->prepare('SELECT id FROM usuarios WHERE id = ?');
			$query->execute([$id]);
			return $query->fetch();
		}
	
		function existeCorreo($correo, $id = 0) {
			if ($id === 0) {
				$query = $this->db->prepare('SELECT id FROM usuarios WHERE correo = ?');
				$query->execute([$correo]);
			} else {
				$query = $this->db->prepare('SELECT id FROM usuarios WHERE correo = ? AND id != ?');
				$query->execute([$correo, $id]);
			}
			return $query->fetch();
		}

		function auth() {
			$data = Flight::request()->data;

			$query = $this->db->prepare('SELECT id, contrasena, rol FROM usuarios WHERE correo = ?');
			$query->execute([$data->correo]);
			$user = $query->fetch();
			if ($user && password_verify($data->contrasena, $user->contrasena)) {
				$now = time();
				$payload = [
					'iat' => $now,
					'nbf' => $now,
					'exp' => $now + 3600,
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

		function crear() {
			$req = Flight::request()->data;
		
			$primerUsuario = $this->totalUsuarios() === 0;
			
			if (!$primerUsuario) {
				$usuarioLogueado = $this->getTokenData();
				if ($usuarioLogueado->rol === 'admin') {
					$rol = (isset($req->rol) && in_array($req->rol, ['admin', 'user'])) ? $req->rol : 'user';
				} else {
					$rol = 'user';
				}
			} else {
				$rol = 'admin';
			}
		
			if (strlen($req->contrasena) < 4 || strlen($req->contrasena) > 72) {
				Flight::halt(400, json_encode(['status' => 'error', 'message' => 'La contraseña debe tener entre 4 y 72 caracteres']));
			}
		
			if (!filter_var($req->correo, FILTER_VALIDATE_EMAIL)) {
				Flight::halt(400, json_encode(['status' => 'error', 'message' => 'Correo electrónico no válido']));
			} elseif ($this->existeCorreo($req->correo)) {
				Flight::halt(400, json_encode(['status' => 'error', 'message' => 'Correo electrónico ya registrado']));
			}
		
			$passHash = password_hash($req->contrasena, PASSWORD_BCRYPT);
			
			$query = $this->db->prepare('INSERT INTO usuarios (nombre, telefono, correo, contrasena, rol) VALUES (?, ?, ?, ?, ?)');
			$query->execute([$req->nombre, $req->telefono, $req->correo, $passHash, $rol]);
			
			$this->listarUno($this->db->lastInsertId(), 201, $primerUsuario);
		}

		function listarTodos() {
			$usuarioLogueado = $this->getTokenData();
	
			if ($usuarioLogueado->rol !== 'admin') {
				Flight::halt(403, json_encode(['status' => 'error', 'message' => 'Acceso denegado']));
			}
			
			$query = $this->db->query('SELECT id, nombre, telefono, correo, actualizado, registrado FROM usuarios');
			Flight::json([
				'status' => 'success',
				'data' => $query->fetchAll()
			]);
		}
	
		function listarUno($id, $status = 200, $primerUsuario = false) {
			if (!$primerUsuario) $this->verificarPermiso($id);
			
			$query = $this->db->prepare('SELECT id, nombre, telefono, correo, actualizado, registrado FROM usuarios WHERE id = ?');
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
	
		function editar($id) {
			$usuarioLogueado = $this->verificarPermiso($id);
			
			$req = Flight::request()->data;
	
			if (!$this->existeUsuario($id)) {
				Flight::halt(404, json_encode(['status' => 'error', 'message' => 'Usuario no encontrado']));
			}
	
			$camposDisponibles = ['nombre', 'telefono', 'correo', 'contrasena'];
	
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
							} elseif ($this->existeCorreo($valor, $id)) {
								Flight::halt(400, json_encode(['status' => 'error', 'message' => 'Correo en uso']));
							}
							break;
						case 'rol':
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
	
			$query = $this->db->prepare($sql);
			if ($query->execute($params)) {
				$this->listarUno($id);
			} else {
				Flight::halt(500, json_encode(['status' => 'error', 'message' => 'Error en la actualización']));
			}
		}
	
		function borrar($id) {
			$usuarioLogueado = $this->verificarPermiso($id);
	
			if ($usuarioLogueado->id == $id && $usuarioLogueado->rol === 'admin') {
				Flight::halt(400, json_encode(['status' => 'error', 'message' => 'No puedes eliminar tu propia cuenta de administrador']));
			}
			
			if (!$this->existeUsuario($id)) {
				Flight::halt(404, json_encode(['status' => 'error', 'message' => 'Usuario no encontrado']));
			}
	
			$query = $this->db->prepare('DELETE FROM usuarios WHERE id = ?');
			$query->execute([$id]);
			Flight::json(['status' => 'success', 'message' => 'Usuario eliminado']);
		}
	}

?>