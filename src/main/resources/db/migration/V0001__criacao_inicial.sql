create table grupo (
  id bigint not null auto_increment,
  nome varchar(255) not null,
primary key (id))
engine = innodb default character set = utf8mb4 collate = utf8mb4_0900_ai_ci;


create table permissao (
  id bigint not null auto_increment,
  descricao varchar(255) not null,
  nome varchar(255) not null,
primary key (id))
engine = innodb default character set = utf8mb4 collate = utf8mb4_0900_ai_ci;


create table grupo_permissao (
  grupo_id bigint not null,
  permissao_id bigint not null,
primary key (grupo_id, permissao_id),
constraint fk_grupo_permissao__permissao foreign key (permissao_id) references permissao (id),
constraint fk_grupo_permissao__grupo     foreign key (grupo_id)     references grupo (id))
engine = innodb default character set = utf8mb4 collate = utf8mb4_0900_ai_ci;


create table usuario (
  id bigint not null auto_increment,
  data_cadastro datetime not null,
  email varchar(255) not null,
  nome varchar(255) not null,
  senha varchar(255) not null,
primary key (id))
engine = innodb default character set = utf8mb4 collate = utf8mb4_0900_ai_ci;


create table usuario_grupo (
  usuario_id bigint not null,
  grupo_id bigint not null,
primary key (usuario_id, grupo_id),
constraint fk_usuario_grupo__usuario foreign key (usuario_id)  references usuario (id),
constraint fk_usuario_grupo__grupo   foreign key (grupo_id)    references grupo   (id))
engine = innodb default character set = utf8mb4 collate = utf8mb4_0900_ai_ci;


