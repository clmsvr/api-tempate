package root.api.v1.controller;


import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import root.api.v1.assembler.GrupoModelAssembler;
import root.api.v1.model.GrupoModel;
import root.api.v1.openapi.UsuarioGrupoControllerOpenApi;
import root.core.security.CheckSecurity;
import root.domain.service.UsuarioService;

@RestController
@RequestMapping(value = "/v1/usuarios/{userId}/grupos")
public class UsuarioGrupoController implements UsuarioGrupoControllerOpenApi {

	@Autowired
	private UsuarioService usuarioService;
	
	@Autowired
	private GrupoModelAssembler assembler;
	
	@CheckSecurity.UsuariosGruposPermissoes.PodeConsultar
	@Override
	@GetMapping
	public List<GrupoModel> listar(@PathVariable Long userId) {
		
		return assembler.toCollectionModel(
				usuarioService.buscar(userId).getGrupos());
	}
	
	@CheckSecurity.UsuariosGruposPermissoes.PodeEditar
	@Override
	@DeleteMapping("/{grupoId}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public ResponseEntity<Void> desassociar(@PathVariable Long userId, @PathVariable Long grupoId) {
		usuarioService.desassociarGrupo(userId, grupoId);
		return ResponseEntity.noContent().build();
	}
	
	@CheckSecurity.UsuariosGruposPermissoes.PodeEditar
	@Override
	@PutMapping("/{grupoId}")
	@ResponseStatus(HttpStatus.NO_CONTENT)
	public ResponseEntity<Void> associar(@PathVariable Long userId, @PathVariable Long grupoId) {
		usuarioService.associarGrupo(userId, grupoId);
		return ResponseEntity.noContent().build();
	}

}