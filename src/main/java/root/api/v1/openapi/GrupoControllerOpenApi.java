package root.api.v1.openapi;

import java.util.List;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import root.api.v1.model.GrupoModel;
import root.api.v1.model.input.GrupoInput;

@SecurityRequirement(name = "security_auth") //26.5
@Tag(name = "Grupo", description = "Gerencia Grupos")
public interface GrupoControllerOpenApi {

	List<GrupoModel> listar();

	GrupoModel buscar(Long grupoId);

	GrupoModel adicionar(GrupoInput grupoInput);

	GrupoModel atualizar(Long grupoId, GrupoInput grupoInput);

	void remover(Long grupoId);

}