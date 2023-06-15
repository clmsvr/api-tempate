package root.api.v1.openapi;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import root.api.exceptionhandler.Problem;
import root.api.v1.model.UsuarioModel;
import root.api.v1.model.input.SenhaInput;
import root.api.v1.model.input.UsuarioInputCreate;
import root.api.v1.model.input.UsuarioInputUpdate;
import root.api.v1.openapi.model.UsuariosModelOpenApi;
import root.core.springdoc.PageableParameter;

@SecurityRequirement(name = "security_auth") //26.5
@Tag(name = "Usuário", description = "Gerencia usuários")
public interface UsuarioControllerOpenApi {

	@PageableParameter  //26.17 custom tab de parametros
    @Operation(
		   summary = "Lista as cozinhas com paginação",
		   responses = {
		     //substituir o excesso de detalhes de "Page" no modelo de resposta com schema "UsuarioModel" da classe UsuariosModelOpenApi
			 @ApiResponse(responseCode = "200", description = "OK",
					     content = @Content(schema = @Schema(implementation = UsuariosModelOpenApi.class))
			 )
	    })
	Page<UsuarioModel> listar(@Parameter(hidden = true) Pageable pageable);

	
	@Operation(summary = "Busca um Usuário por ID", responses = {
			@ApiResponse(responseCode = "200"),
			@ApiResponse(responseCode = "400", description = "ID inválido",
					content = @Content(schema = @Schema(implementation = Problem.class))),
			@ApiResponse(responseCode = "404", description = "Usuário não encontrado",
					content = @Content(schema = @Schema(implementation = Problem.class)))
	})
	UsuarioModel buscar(@Parameter(description = "ID do Usuário", example = "1", required = true) Long usuarioId);

	
	@Operation(summary = "Cadastra um Usuário", responses = {
			@ApiResponse(responseCode = "201", description = "Cozinha cadastrada"),
	})
	UsuarioModel adicionar(@RequestBody(description = "Representação de um Usuário", required = true)  UsuarioInputCreate usuarioInput);

	
	
	@Operation(summary = "Atualiza um Usuario", responses = {
			@ApiResponse(responseCode = "200", description = "Usuário atualizado"),
			@ApiResponse(responseCode = "404", description = "Usuário não encontrado",
					content = @Content(schema = @Schema(implementation = Problem.class))),
	})
	UsuarioModel atualizar(
			@Parameter(description = "ID de um Usuário", example = "1", required = true) Long usuarioId, 
			@RequestBody(description = "Representação de um Usuário com os novos dados", required = true) UsuarioInputUpdate usuarioInput);

	
	@Operation(summary = "Exclui um Usuário por ID", responses = {
			@ApiResponse(responseCode = "204", description = "Usuário excluído"),
			@ApiResponse(responseCode = "404", description = "Usuário não encontrado",
					content = @Content(schema = @Schema(implementation = Problem.class)))
	})
	void remover(@Parameter(description = "ID de um Usuário", example = "1", required = true) Long usuarioId);

	void atualizarSenha(Long usuarioId, SenhaInput senhaInput);
}