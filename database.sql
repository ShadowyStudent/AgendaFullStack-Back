create database if not exists Agenda;
use Agenda;

create table usuarios (
  id int auto_increment primary key,
  nombre_de_usuario varchar(50) unique not null,
  password varchar(255) not null,
  fecha_registro timestamp default current_timestamp,
  token varchar(255),
  avatar varchar(255)
);

create table contactos (
  id int auto_increment primary key,
  usuario_id int not null,
  nombre varchar(100) not null,
  apellido varchar(100),
  telefono varchar(20) not null,
  email varchar(120),
  direccion varchar(255),
  notas text,
  foto varchar(255),
  fecha_creacion timestamp default current_timestamp,
  constraint fk_contactos_usuario
    foreign key (usuario_id) references usuarios(id)
    on delete cascade
);

create index idx_contactos_usuario_id on contactos(usuario_id);