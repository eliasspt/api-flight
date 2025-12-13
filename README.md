# User Management API (FlightPHP + JWT)
Una API REST robusta y ligera para la gestión de usuarios, construida con FlightPHP, JWT (JSON Web Tokens) y PDO. Este sistema implementa un control de acceso basado en roles (RBAC) y lógica de "primer registro como administrador".

# 🚀 Características
<ul>
    <li><strong>Autenticación segura:</strong> Implementación de JWT con margen de tiempo (<code>leeway</code>) configurable.</li>
    <li><strong>Gestión de Roles (RBAC):</strong> Roles de admin y user con permisos diferenciados.</li>
    <li><strong>Primer Registro Inteligente:</strong> El primer usuario registrado en la base de datos recibe automáticamente el rol de admin.</li>
    <li><strong>Actualización Dinámica:</strong> Permite actualizar campos individuales o múltiples en una sola petición.</li>
    <li><strong>Protección de Integridad:</strong> Los administradores no pueden eliminarse a sí mismos ni degradar su propio rango por error.</li>
    <li><strong>Seguridad:</strong> Uso de password_hash con algoritmo BCRYPT y prevención de SQL Injection mediante consultas preparadas en PDO.</li>
</ul>

# 🛠️ RequisitosPHP 7.4 o superior.MySQL / MariaDB.Composer.📦 InstalaciónClonar el repositorio:Bashgit clone https://github.com/tu-usuario/api-flight-usuarios.git
cd api-flight-usuarios
Instalar dependencias:Bashcomposer install
Configurar variables de entorno:Crea un archivo .env en la raíz del proyecto basándote en los siguientes valores:Fragmento de códigoDB_HOST=localhost
DB_NAME=nombre_tu_db
DB_USER=tu_usuario
DB_PASS=tu_contraseña
SECRET_KEY_APP=una_clave_muy_segura_y_larga
Crear la base de datos:Ejecuta el siguiente SQL para crear la tabla necesaria:SQLCREATE TABLE `usuarios` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `nombre` VARCHAR(100) NOT NULL,
    `telefono` VARCHAR(16) NOT NULL,
    `correo` VARCHAR(150) NOT NULL,
    `rol` ENUM('admin', 'user') NOT NULL DEFAULT 'user',
    `contrasena` VARCHAR(255) NOT NULL,
    `actualizado` TIMESTAMP NOT NULL DEFAULT(now()) ON UPDATE CURRENT_TIMESTAMP,
    `registrado` TIMESTAMP NOT NULL DEFAULT(now()),
    PRIMARY KEY (`id`),
    UNIQUE INDEX `correo` (`correo`)
) ENGINE = InnoDB;
🛣️ Endpoints PrincipalesMétodoRutaAccesoDescripciónPOST/authPúblicoAutenticación y obtención de Token.POST/usuariosPúblico/AdminRegistro de usuarios (Primer registro = Admin).GET/usuariosAdminLista todos los usuarios registrados.GET/usuarios/@idAdmin/DueñoObtiene detalles de un usuario específico.PUT/usuarios/@idAdmin/DueñoEdición dinámica de datos del perfil.DELETE/usuarios/@idAdmin/DueñoElimina un usuario (Protección de auto-borrado).🔐 Lógica de PermisosAdmin: Puede listar todos los usuarios, ver cualquier perfil, editar cualquier campo (incluyendo el rol de otros) y borrar cualquier cuenta (excepto la propia).User: Solo puede ver y editar su propio perfil. No puede visualizar la lista completa de usuarios ni cambiar su propio rol a administrador.¿Cómo probarlo?Puedes usar archivos .http en VS Code, Postman o Insomnia. Recuerda incluir el token en el encabezado de autorización para las rutas protegidas:Authorization: Bearer TU_JWT_AQUI