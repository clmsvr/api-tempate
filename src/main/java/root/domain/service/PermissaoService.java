package root.domain.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import root.domain.exception.NotFoundException;
import root.domain.model.Permissao;
import root.domain.repository.PermissaoRepository;

@Service
public class PermissaoService {

	private static final String MSG_NOT_FOUND = "Não existe um cadastro de Permissão com código %d";

    @Autowired
    private PermissaoRepository permissaoRepository;
    
    public Permissao buscar(Long permissaoId) {
		return permissaoRepository.findById(permissaoId)
				.orElseThrow(() -> new NotFoundException(String.format(MSG_NOT_FOUND, permissaoId) ) );	

    }
}