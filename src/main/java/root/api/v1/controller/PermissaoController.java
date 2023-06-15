package root.api.v1.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import root.api.v1.assembler.PermissaoModelAssembler;
import root.api.v1.model.PermissaoModel;
import root.api.v1.openapi.PermissaoControllerOpenApi;
import root.core.security.CheckSecurity;
import root.domain.repository.PermissaoRepository;

@RestController
@RequestMapping("/v1/permissoes")
public class PermissaoController implements PermissaoControllerOpenApi {

	@Autowired
	private PermissaoRepository repository;
	
	@Autowired
	private PermissaoModelAssembler assembler;
	
	@CheckSecurity.UsuariosGruposPermissoes.PodeConsultar
	@Override
	@GetMapping
	public List<PermissaoModel> listar() {
		return assembler.toCollectionModel(repository.findAll());
	}	
}