package root.api.v1.openapi;

import java.util.List;

import org.springframework.http.ResponseEntity;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import root.api.v1.model.PermissaoModel;

@SecurityRequirement(name = "security_auth") //26.5
@Tag(name = "Grupo_Permissão", description = "Gerencia Permissões de Grupos")
public interface GrupoPermissaoControllerOpenApi {

	List<PermissaoModel> listar(Long grupoId);

	ResponseEntity<Void> desassociar(Long grupoId, Long permissaoId);

	ResponseEntity<Void> associar(Long grupoId, Long permissaoId);

}