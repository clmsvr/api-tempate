package root.core.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import lombok.extern.slf4j.Slf4j;
import root.domain.model.Usuario;
import root.domain.repository.UsuarioRepository;

@Slf4j
@Component
public class AlgaSecurity {

	@Autowired
	private UsuarioRepository userRepository;
	
	public Authentication getAuthentication() {
		return SecurityContextHolder.getContext().getAuthentication();
	}
	
	//se retornar null pode gerar bug
	public Long getUsuarioId() {
		//eh um JWT porque estamos configurados como resouce server.
		Jwt jwt = (Jwt) getAuthentication().getPrincipal();
		
		String userid = jwt.getClaim("usuario_id");
		if(userid == null) {
			return -1l;
		}
		
		try {
			return Long.parseLong(userid);
		} catch (Exception e) {
			log.info("Falha no parser do id do usuario: "+userid);
			return -10l;
		}
	}
	
	//minha idea nao funcionou
    //Se for um ClientCredential Token verificar se é teste e se há elevação de authoridade
	@Transactional(readOnly = true)
	public Long verifyAndDefineTestAuthorities(Jwt jwt)
	{
		//localizar escopo de teste
		Optional<? extends GrantedAuthority> op = 
				getAuthentication().getAuthorities().stream()
				.filter(authority -> authority.getAuthority().startsWith("SCOPE_test:"))
				.findFirst();
		if (op.isEmpty()) return -1L; //nao tem ecopo de teste
		
		//identificar usuario pelo email do escopo
		String userEmail = op.get().getAuthority().substring(11);
		Optional<Usuario> user = userRepository.findByEmail(userEmail);
		if (user.isEmpty()) return -1L; //usuario mencionado no escopo nao encontrado

		//buscar permissoes do usuario
		var newAuthorities = getAuthorities(user.get());

		//adicionar novas authorities
		Collection<? extends GrantedAuthority> currentAuthorities = 
				SecurityContextHolder.getContext().getAuthentication().getAuthorities();
		
		List<GrantedAuthority> updatedAuthorities = new ArrayList<GrantedAuthority>();
		updatedAuthorities.addAll(newAuthorities);
		updatedAuthorities.addAll(currentAuthorities);

		SecurityContextHolder.getContext().setAuthentication(
		        new UsernamePasswordAuthenticationToken(
		                SecurityContextHolder.getContext().getAuthentication().getPrincipal(),
		                SecurityContextHolder.getContext().getAuthentication().getCredentials(),
		                updatedAuthorities)
		);	
		
		return user.get().getId();
	}
	
	private Collection<GrantedAuthority> getAuthorities(Usuario usuario) 
	{
		return usuario.getGrupos().stream()
				.flatMap(grupo -> grupo.getPermissoes().stream())
				.map(permissao -> new SimpleGrantedAuthority(permissao.getNome().toUpperCase()))
				.collect(Collectors.toSet()); //Set: usuario pode estar em dois grupos com permissoes repetidas
		//return Collections.emptyList();
	}
	
	//solucao do thiago para evitar bug quando metodo acima retornava null.
	//precisa ainda alterar as anotações para usar este metodo
	public boolean usuarioAutenticadoIgual(Long usuarioId) {
		return getUsuarioId() != null && usuarioId != null
				&& getUsuarioId().equals(usuarioId);
	}
	
	
	//Daqui para baixo sao metodos criados para autorizar os link HAL nas respostas.
	//Podemos reescrever as anotações de CheckSecurity utilizando estes methodos.
	
	
	public boolean hasAuthority(String authorityName) {
		return getAuthentication().getAuthorities().stream()
				.anyMatch(authority -> authority.getAuthority().equals(authorityName));
	}
	
	//23.40 daqui pra baixo
	
	public boolean isAutenticado() {
		return getAuthentication().isAuthenticated();
	}
	
	public boolean temEscopoEscrita() {
		return hasAuthority("SCOPE_write");
	}
	
	public boolean temEscopoLeitura() {
		return hasAuthority("SCOPE_read");
	}
	
	public boolean podeConsultarUsuariosGruposPermissoes() {
		return temEscopoLeitura() && hasAuthority("CONSULTAR_USUARIOS_GRUPOS_PERMISSOES");
	}
	
	public boolean podeEditarUsuariosGruposPermissoes() {
		return temEscopoEscrita() && hasAuthority("EDITAR_USUARIOS_GRUPOS_PERMISSOES");
	}
	
	public boolean podePesquisarPedidos() {
		return isAutenticado() && temEscopoLeitura();
	}
	
	public boolean podeConsultarFormasPagamento() {
		return isAutenticado() && temEscopoLeitura();
	}
	
	public boolean podeConsultarCidades() {
		return isAutenticado() && temEscopoLeitura();
	}
	
	public boolean podeConsultarEstados() {
		return isAutenticado() && temEscopoLeitura();
	}

	public boolean podeConsultarEstatisticas() {
		return temEscopoLeitura() && hasAuthority("GERAR_RELATORIOS");
	}
}