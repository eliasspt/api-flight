CREATE TABLE `usuarios` (
    `id` INT NOT NULL AUTO_INCREMENT,
    `nombre` VARCHAR(100) NOT NULL COLLATE 'utf8mb4_unicode_ci',
    `telefono` VARCHAR(16) NOT NULL COLLATE 'utf8mb4_unicode_ci',
    `correo` VARCHAR(150) NOT NULL COLLATE 'utf8mb4_unicode_ci',
    `rol` ENUM('admin', 'user') NOT NULL DEFAULT 'user' COLLATE 'utf8mb4_unicode_ci',
    `contrasena` VARCHAR(255) NOT NULL COLLATE 'utf8mb4_unicode_ci',
    `actualizado` TIMESTAMP NOT NULL DEFAULT(now()) ON UPDATE CURRENT_TIMESTAMP,
    `registrado` TIMESTAMP NOT NULL DEFAULT(now()),
    PRIMARY KEY (`id`) USING BTREE,
    UNIQUE INDEX `correo` (`correo`) USING BTREE
) COLLATE = 'utf8mb4_unicode_ci' ENGINE = InnoDB;
