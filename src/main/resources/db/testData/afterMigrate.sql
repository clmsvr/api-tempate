set foreign_key_checks = 0;

# 24.15 Locks para permitir mais de uma instancia da aplicação 
# serem levantedas simultaneamente.

lock tables grupo write, grupo_permissao write, permissao write,
    usuario write, usuario_grupo write,
    oauth2_authorization_consent write,
    oauth2_authorization write,
    oauth2_registered_client write,
    SPRING_SESSION_ATTRIBUTES write, SPRING_SESSION write ; 
    
truncate usuario;
truncate permissao;
truncate grupo;
truncate grupo_permissao;
truncate usuario_grupo;
truncate SPRING_SESSION_ATTRIBUTES;
truncate SPRING_SESSION;
truncate oauth2_authorization_consent;
truncate oauth2_authorization;
truncate oauth2_registered_client;

set foreign_key_checks = 1;

insert into permissao (id, nome, descricao) values (1, 'EDITAR_COZINHAS', 'Permite editar cozinhas');
insert into permissao (id, nome, descricao) values (2, 'EDITAR_FORMAS_PAGAMENTO', 'Permite criar ou editar formas de pagamento');
insert into permissao (id, nome, descricao) values (3, 'EDITAR_CIDADES', 'Permite criar ou editar cidades');
insert into permissao (id, nome, descricao) values (4, 'EDITAR_ESTADOS', 'Permite criar ou editar estados');
insert into permissao (id, nome, descricao) values (5, 'CONSULTAR_USUARIOS_GRUPOS_PERMISSOES', 'Permite consultar usuários, grupos e permissões');
insert into permissao (id, nome, descricao) values (6, 'EDITAR_USUARIOS_GRUPOS_PERMISSOES', 'Permite criar ou editar usuários, grupos e permissões');
insert into permissao (id, nome, descricao) values (7, 'EDITAR_RESTAURANTES', 'Permite criar, editar ou gerenciar restaurantes');
insert into permissao (id, nome, descricao) values (8, 'CONSULTAR_PEDIDOS', 'Permite consultar pedidos');
insert into permissao (id, nome, descricao) values (9, 'GERENCIAR_PEDIDOS', 'Permite gerenciar pedidos');
insert into permissao (id, nome, descricao) values (10, 'GERAR_RELATORIOS', 'Permite gerar relatórios');

insert into grupo (id, nome) 
values (1, 'Gerente'), (2, 'Vendedor'), (3, 'Secretária'), (4, 'Cadastrador');

# Adiciona todas as permissoes no grupo do gerente
insert into grupo_permissao (grupo_id, permissao_id)
select 1, id from permissao;

# Adiciona permissoes no grupo do vendedor
insert into grupo_permissao (grupo_id, permissao_id)
select 2, id from permissao where nome like 'CONSULTAR_%';

insert into grupo_permissao (grupo_id, permissao_id)
select 2, id from permissao where nome = 'EDITAR_RESTAURANTES';

# Adiciona permissoes no grupo do auxiliar
insert into grupo_permissao (grupo_id, permissao_id)
select 3, id from permissao where nome like 'CONSULTAR_%';

# Adiciona permissoes no grupo cadastrador
insert into grupo_permissao (grupo_id, permissao_id)
select 4, id from permissao where nome like '%_RESTAURANTES';

insert into usuario (id, nome, email, senha, data_cadastro) values
(1, 'João da Silva', 'joao.ger@algafood.com.br', '$2y$12$NSsM4gEOR7MKogflKR7GMeYugkttjNhAJMvFdHrBLaLp2HzlggP5W', utc_timestamp),
(2, 'Maria Joaquina', 'maria.vnd@algafood.com.br', '$2y$12$NSsM4gEOR7MKogflKR7GMeYugkttjNhAJMvFdHrBLaLp2HzlggP5W', utc_timestamp),
(3, 'José Souza', 'jose.aux@algafood.com.br', '$2y$12$NSsM4gEOR7MKogflKR7GMeYugkttjNhAJMvFdHrBLaLp2HzlggP5W', utc_timestamp),
(4, 'Sebastião Martins', 'sebastiao.cad@algafood.com.br', '$2y$12$NSsM4gEOR7MKogflKR7GMeYugkttjNhAJMvFdHrBLaLp2HzlggP5W', utc_timestamp),
(5, 'Manoel Lima', 'manoel.loja@gmail.com', '$2y$12$NSsM4gEOR7MKogflKR7GMeYugkttjNhAJMvFdHrBLaLp2HzlggP5W', utc_timestamp),
(6, 'Débora Mendonça', 'claudioms0909+debora@gmail.com', '$2y$12$NSsM4gEOR7MKogflKR7GMeYugkttjNhAJMvFdHrBLaLp2HzlggP5W', utc_timestamp),
(7, 'Carlos Lima', 'claudioms0909+carlos@gmail.com', '$2y$12$NSsM4gEOR7MKogflKR7GMeYugkttjNhAJMvFdHrBLaLp2HzlggP5W', utc_timestamp);

insert into usuario_grupo (usuario_id, grupo_id) 
values (1, 1), (1, 2), (2, 2), (3, 3), (4, 4);

INSERT INTO `oauth2_registered_client` 
(`id`, `client_id`, `client_id_issued_at`, `client_secret`, `client_secret_expires_at`, 
 `client_name`, `client_authentication_methods`, `authorization_grant_types`, `redirect_uris`, 
 `post_logout_redirect_uris`, `scopes`, 
 `client_settings`, `token_settings`
 ) VALUES (
"algafood-web","algafood-web","2023-06-04 11:18:04","$2a$10$ak.wHLUhZHHRHBI4/X9KR.3PWSn.6h6ebcmhUf02n4QzFpC9bUbBy",NULL,
"algafood-web","client_secret_basic","client_credentials","",
"","read,write",

"{\"@class\":\"java.util.Collections$UnmodifiableMap\",
  \"settings.client.require-proof-key\":false,
  \"settings.client.require-authorization-consent\":false}",

"{\"@class\":\"java.util.Collections$UnmodifiableMap\",
  \"settings.token.reuse-refresh-tokens\":true,
  \"settings.token.id-token-signature-algorithm\":[\"org.springframework.security.oauth2.jose.jws.SignatureAlgorithm\",\"RS256\"],
  \"settings.token.access-token-time-to-live\":[\"java.time.Duration\",1800.000000000],
  \"settings.token.access-token-format\":{\"@class\":\"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat\",\"value\":\"reference\"},
  \"settings.token.refresh-token-time-to-live\":[\"java.time.Duration\",3600.000000000],
  \"settings.token.authorization-code-time-to-live\":[\"java.time.Duration\",300.000000000],
  \"settings.token.device-code-time-to-live\":[\"java.time.Duration\",300.000000000]}"
);

INSERT INTO `oauth2_registered_client` 
(`id`, `client_id`, `client_id_issued_at`, `client_secret`, `client_secret_expires_at`, 
 `client_name`, `client_authentication_methods`, `authorization_grant_types`, `redirect_uris`, 
 `post_logout_redirect_uris`, `scopes`, 
 `client_settings`, `token_settings`
) VALUES (
 "device1","device1","2023-06-04 11:18:04","$2a$10$OsvixDzroXaXtGKsTtww5O3AWnCaeRWQRRFDB/oaL3KECUaG1uhAy",NULL,
 "device1","client_secret_basic","refresh_token,urn:ietf:params:oauth:grant-type:device_code","",
 "","read,openid,write",
 
 "{\"@class\":\"java.util.Collections$UnmodifiableMap\",
   \"settings.client.require-proof-key\":false,
   \"settings.client.require-authorization-consent\":true}",
   
 "{\"@class\":\"java.util.Collections$UnmodifiableMap\",
   \"settings.token.reuse-refresh-tokens\":false,
   \"settings.token.id-token-signature-algorithm\":[\"org.springframework.security.oauth2.jose.jws.SignatureAlgorithm\",\"RS256\"],
   \"settings.token.access-token-time-to-live\":[\"java.time.Duration\",1800.000000000],
   \"settings.token.access-token-format\":{\"@class\":\"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat\",\"value\":\"self-contained\"},
   \"settings.token.refresh-token-time-to-live\":[\"java.time.Duration\",43200.000000000],
   \"settings.token.authorization-code-time-to-live\":[\"java.time.Duration\",300.000000000],
   \"settings.token.device-code-time-to-live\":[\"java.time.Duration\",300.000000000]}"
);

INSERT INTO `oauth2_registered_client` 
(`id`, `client_id`, `client_id_issued_at`, `client_secret`, `client_secret_expires_at`, 
 `client_name`, `client_authentication_methods`, `authorization_grant_types`, `redirect_uris`, 
 `post_logout_redirect_uris`, `scopes`, 
 `client_settings`, `token_settings`
) VALUES (
"javascript1","javascript1","2023-06-04 11:18:04","$2a$10$UbGEG9PKi1jXoVGSGVBJ0Oq/q/GuzSc4Gd2lKKWJ5IcL/McEjk8z6",NULL,
"javascript1","client_secret_basic","refresh_token,client_credentials,authorization_code","http://127.0.0.1:5555/index.html",
"","read,openid,write",

"{\"@class\":\"java.util.Collections$UnmodifiableMap\",
  \"settings.client.require-proof-key\":false,
  \"settings.client.require-authorization-consent\":true}",
  
"{\"@class\":\"java.util.Collections$UnmodifiableMap\",
  \"settings.token.reuse-refresh-tokens\":false,
  \"settings.token.id-token-signature-algorithm\":[\"org.springframework.security.oauth2.jose.jws.SignatureAlgorithm\",\"RS256\"],
  \"settings.token.access-token-time-to-live\":[\"java.time.Duration\",1800.000000000],
  \"settings.token.access-token-format\":{\"@class\":\"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat\",\"value\":\"self-contained\"},
  \"settings.token.refresh-token-time-to-live\":[\"java.time.Duration\",43200.000000000],
  \"settings.token.authorization-code-time-to-live\":[\"java.time.Duration\",300.000000000],
  \"settings.token.device-code-time-to-live\":[\"java.time.Duration\",300.000000000]}"
);

INSERT INTO `oauth2_registered_client` 
(`id`, `client_id`, `client_id_issued_at`, `client_secret`, `client_secret_expires_at`, 
 `client_name`, `client_authentication_methods`, `authorization_grant_types`, `redirect_uris`, 
 `post_logout_redirect_uris`, `scopes`, `client_settings`, `token_settings`
) VALUES (
"postman1","postman1","2023-06-04 11:18:04","$2a$10$Df..NHtXDTlXuvYFf4QldeW6kmyxU39lpD.aUy9oMLXkA0skDFmFS",NULL,
"postman1","client_secret_basic","refresh_token,client_credentials,authorization_code","http://localhost:8080/swagger-ui/oauth2-redirect.html,https://oidcdebugger.com/debug,http://127.0.0.1:8080/authorize,https://oauth.pstmn.io/v1/callback",
"http://127.0.0.1:8080/","read,write",

"{\"@class\":\"java.util.Collections$UnmodifiableMap\",
  \"settings.client.require-proof-key\":false,
  \"settings.client.require-authorization-consent\":true}",
  
"{\"@class\":\"java.util.Collections$UnmodifiableMap\",
  \"settings.token.reuse-refresh-tokens\":false,
  \"settings.token.id-token-signature-algorithm\":[\"org.springframework.security.oauth2.jose.jws.SignatureAlgorithm\",\"RS256\"],
  \"settings.token.access-token-time-to-live\":[\"java.time.Duration\",10800.000000000],
  \"settings.token.access-token-format\":{\"@class\":\"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat\",\"value\":\"self-contained\"},
  \"settings.token.refresh-token-time-to-live\":[\"java.time.Duration\",43200.000000000],
  \"settings.token.authorization-code-time-to-live\":[\"java.time.Duration\",300.000000000],
  \"settings.token.device-code-time-to-live\":[\"java.time.Duration\",300.000000000]}"
);

INSERT INTO `oauth2_registered_client` 
(`id`, `client_id`, `client_id_issued_at`, `client_secret`, `client_secret_expires_at`, 
`client_name`, `client_authentication_methods`, `authorization_grant_types`, `redirect_uris`, 
`post_logout_redirect_uris`, `scopes`, `client_settings`, `token_settings`
) VALUES (
"resource-server","resource-server","2023-06-04 11:18:04","$2a$10$RhZHrEkm.PMlN3Pkov6ECuDONSTsBcO9UwO9tJXXaWhdn/DSTcd6q",NULL,
"resource-server","client_secret_basic","client_credentials","",
"","",

"{\"@class\":\"java.util.Collections$UnmodifiableMap\",
  \"settings.client.require-proof-key\":false,
  \"settings.client.require-authorization-consent\":false}",
  
"{\"@class\":\"java.util.Collections$UnmodifiableMap\",
  \"settings.token.reuse-refresh-tokens\":true,
  \"settings.token.id-token-signature-algorithm\":[\"org.springframework.security.oauth2.jose.jws.SignatureAlgorithm\",\"RS256\"],
  \"settings.token.access-token-time-to-live\":[\"java.time.Duration\",300.000000000],
  \"settings.token.access-token-format\":{\"@class\":\"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat\",\"value\":\"self-contained\"},
  \"settings.token.refresh-token-time-to-live\":[\"java.time.Duration\",3600.000000000],
  \"settings.token.authorization-code-time-to-live\":[\"java.time.Duration\",300.000000000],
  \"settings.token.device-code-time-to-live\":[\"java.time.Duration\",300.000000000]}"
);


# 24.15
unlock tables;

