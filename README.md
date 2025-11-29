# Proyecto Unidad 4 – (Final) Aplicación Full Stack: Back-End (PHP + API REST + MySQL/MariaDB)

## Objetivo
Proveer una API REST en PHP que gestione la lógica del servidor para una agenda: autenticación, autorización y operaciones CRUD sobre contactos con persistencia en MySQL/MariaDB.

## Funcionamiento (muy breve)
El backend valida credenciales y emite un JWT; el frontend envía ese token en `Authorization: Bearer <token>` en cada petición. Los endpoints protegidos verifican la firma del JWT (y, en esta implementación, pueden validar el token contra la base de datos como respaldo). Las rutas expuestas implementan autenticación y CRUD para contactos y devuelven respuestas JSON con códigos HTTP apropiados.

## Datos del estudiante
- **Nombre:** Álvarez López Miguel
- **Número de control:** 2227001
- **Grupo:** S5B 
- **Materia:** Programacion Web
