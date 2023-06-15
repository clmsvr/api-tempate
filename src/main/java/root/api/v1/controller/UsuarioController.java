package root.api.v1.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;
import root.api.v1.assembler.UsuarioModelAssembler;
import root.api.v1.model.UsuarioModel;
import root.api.v1.model.input.SenhaInput;
import root.api.v1.model.input.UsuarioInputCreate;
import root.api.v1.model.input.UsuarioInputUpdate;
import root.api.v1.openapi.UsuarioControllerOpenApi;
import root.core.security.CheckSecurity;
import root.domain.model.Usuario;
import root.domain.repository.UsuarioRepository;
import root.domain.service.UsuarioService;

@RestController
@RequestMapping("/v1/usuarios")
public class UsuarioController implements UsuarioControllerOpenApi {

	@Autowired
	private UsuarioRepository usuarioRepository;
	
	@Autowired
	private UsuarioService usuarioService;
	
	//11.20
	@Autowired
	private UsuarioModelAssembler assembler;
	
	@CheckSecurity.UsuariosGruposPermissoes.PodeConsultar
	@Override
	@GetMapping
	public Page<UsuarioModel> listar(@PageableDefault(size=10) Pageable pageable) 
	{
		Page<Usuario> usersPage = usuarioRepository.findAll(pageable);
		
		List<UsuarioModel> usersModel = 
				assembler.toCollectionModel(usersPage.getContent());
		
		Page<UsuarioModel> usersModelPage = 
				new PageImpl<>(usersModel, pageable,	
						       usersPage.getTotalElements());
		
		return usersModelPage;		
	}
	
//	public List<UsuarioModel> listar_old() {
//		return assembler.toCollectionModel(
//				usuarioRepository.findAll());
//	}
	
	@CheckSecurity.UsuariosGruposPermissoes.PodeConsultar
	@Override
	@GetMapping("/{usuarioId}")
	public UsuarioModel buscar(@PathVariable Long usuarioId) {
		
		return  assembler.toModel(
				usuarioService.buscar(usuarioId));
	}
	
	@CheckSecurity.UsuariosGruposPermissoes.PodeEditar
	@Override
	@PostMapping
	@ResponseStatus(HttpStatus.CREATED)
	public UsuarioModel adicionar(@RequestBody @Valid UsuarioInputCreate usuarioInput) {
		
		Usuario usuario = assembler.toDomainObject(usuarioInput);
		return assembler.toModel(usuarioService.criar(usuario));
	}
	
	@CheckSecurity.UsuariosGruposPermissoes.PodeAlterarUsuario
	@Override
	@PutMapping("/{usuarioId}")
	public UsuarioModel atualizar(@PathVariable Long usuarioId, 
			@RequestBody @Valid UsuarioInputUpdate usuarioInput) {
		
		return assembler.toModel(
				usuarioService.atualizar(usuarioId, usuarioInput));
	}
	
	@CheckSecurity.UsuariosGruposPermissoes.PodeEditar
	@Override
	@DeleteMapping("/{usuarioId}")
	@ResponseStatus(code = HttpStatus.NO_CONTENT)
	public void remover(@PathVariable Long usuarioId) {
		usuarioService.excluir(usuarioId);	
	}	
	
	@CheckSecurity.UsuariosGruposPermissoes.PodeAlterarPropriaSenha
	@Override
	@PutMapping("/{usuarioId}/senha")
	@ResponseStatus(code = HttpStatus.NO_CONTENT)
	public void atualizarSenha(@PathVariable Long usuarioId, 
			@RequestBody @Valid SenhaInput senhaInput) {
		
		usuarioService.atualizarSenha(
						usuarioId, 
						senhaInput.getSenhaAtual(), 
						senhaInput.getNovaSenha());
	}	
}