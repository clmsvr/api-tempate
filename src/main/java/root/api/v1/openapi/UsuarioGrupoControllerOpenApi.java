package root.api.v1.openapi;

import java.util.List;

import org.springframework.http.ResponseEntity;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import root.api.v1.model.GrupoModel;

@SecurityRequirement(name = "security_auth") //26.5
@Tag(name = "Grupo_Usuário", description = "Gerencia Usuários e seus Grupos")
public interface UsuarioGrupoControllerOpenApi {

	List<GrupoModel> listar(Long userId);

	ResponseEntity<Void> desassociar(Long userId, Long grupoId);

	ResponseEntity<Void> associar(Long userId, Long grupoId);

}