package root.domain.service;

import java.util.Optional;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import jakarta.transaction.Transactional;
import root.api.v1.model.input.UsuarioInputUpdate;
import root.domain.exception.BusinessException;
import root.domain.exception.InUseException;
import root.domain.exception.NotFoundException;
import root.domain.model.Grupo;
import root.domain.model.Usuario;
import root.domain.repository.UsuarioRepository;

@Service
public class UsuarioService {

	private static final String MSG_IN_USE = "Usuario de código %d não pode ser removida, pois está em uso";
	private static final String MSG_NOT_FOUND = "Não existe um cadastro de Usuario com código %d";
	@Autowired
	private UsuarioRepository usuarioRepository;
	@Autowired
	GrupoService grupoService;
	@Autowired
	private ModelMapper mapper;
	@Autowired
	private PasswordEncoder passEncoder;
	
	
	@Transactional
	public Usuario atualizar(Long usuarioId, UsuarioInputUpdate usuarioInput)
	throws NotFoundException, BusinessException
	{
		Optional<Usuario> opt = usuarioRepository.findById(usuarioId);
		
		if (opt.isEmpty()) 
			throw new NotFoundException(String.format(MSG_NOT_FOUND, usuarioId));

		//verificar email
		//fatos interessantes de JPA na aula 12.11 - pela forma que fiz nao deu erro
		var o = usuarioRepository.findByEmail(usuarioInput.getEmail());
		if (o.isPresent() && o.get().getId() != usuarioId)
		{
			throw new BusinessException("Já existe um usuário cadastrado com email: "+ usuarioInput.getEmail());
		}
		
		Usuario usuarioDB = opt.get();
		mapper.map(usuarioInput, usuarioDB);//entrada nao tem os campos acima			
		
		return usuarioRepository.save(usuarioDB);
	}
	
	@Transactional
	public Usuario criar(Usuario usuario) 
	throws BusinessException
	{
		//verificar email
		var o = usuarioRepository.findByEmail(usuario.getEmail());
		if (o.isPresent())
		{
			throw new BusinessException("Já existe um usuário cadastrado com email: "+ usuario.getEmail());
		}
		usuario.setSenha(passEncoder.encode(usuario.getSenha()));
		usuario.setId(null);		
		return usuarioRepository.save(usuario);
	}
	
	@Transactional
	public void excluir(Long usuarioId) 
	throws NotFoundException, InUseException
	{
		if(usuarioRepository.findById(usuarioId).isEmpty())
			throw new NotFoundException(String.format(MSG_NOT_FOUND, usuarioId));
		
		try {
			//If the entity is not found in the persistence store it is silently ignored.
			usuarioRepository.deleteById(usuarioId);
			//por causa do agora estendido contexto transacional, nao ha garantias de que a operação vai ser executada agora para capturarmos as exceptions. 
			//Nao estamos capturando as exceptions. operaçoes estao enfileiradas no EntityManager
			//Precisamos usar o comit() para executar as operacoes e capturarmos as exceptions.
			usuarioRepository.flush();
		} catch (EmptyResultDataAccessException e) {
			throw e;  //nao é mais lancada
		
		} catch (DataIntegrityViolationException e) {
			throw new InUseException(
				String.format(MSG_IN_USE, usuarioId));
		}
	}
	
	public Usuario buscar(Long usuarioId) 
	throws NotFoundException
	{
		return usuarioRepository.findById(usuarioId)
				.orElseThrow(() -> new NotFoundException(String.format(MSG_NOT_FOUND, usuarioId) ) );	
	}

	public Usuario buscarPorEmail(String email) 
	throws NotFoundException
	{
		return usuarioRepository.findByEmail(email)
				.orElseThrow(() -> new NotFoundException(String.format(MSG_NOT_FOUND, email) ) );	
	}

	@Transactional  //!!!!
	public void atualizarSenha(Long usuarioId, String senhaAtual, String novaSenha)
	throws NotFoundException
	{
		Optional<Usuario> opt = usuarioRepository.findById(usuarioId);
		
		if (opt.isEmpty()) 
			throw new NotFoundException(String.format(MSG_NOT_FOUND, usuarioId));

		Usuario usuarioDB = opt.get();
		
		if (passEncoder.matches(senhaAtual, usuarioDB.getSenha()))
			usuarioDB.setSenha(passEncoder.encode(novaSenha));
		else
			throw new BusinessException("Senhas atual inválida.");
		
		//nao precisa mas PRECISA DO CONTEXTO TRANSACIONAL @Transactional
		//veja 12.10 !!
		//usuarioRepository.save(usuarioDB);
	}

	@Transactional 
	public void desassociarGrupo(Long userId, Long grupoId)
	throws NotFoundException
	{
		Usuario usuario = buscar(userId);
		Grupo grupo = grupoService.buscar(grupoId);
		usuario.removerGrupo(grupo);
	}

	@Transactional 
	public void associarGrupo(Long userId, Long grupoId) 
	throws NotFoundException
	{
		Usuario usuario = buscar(userId);
		Grupo grupo = grupoService.buscar(grupoId);
		usuario.adicionarGrupo(grupo);		
	}
}