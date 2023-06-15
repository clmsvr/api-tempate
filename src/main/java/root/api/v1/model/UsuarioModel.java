package root.api.v1.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UsuarioModel{

	private Long id;
	private String nome;
	private String email;
	//private String senha;
	//private List<GrupoModel> grupos = new ArrayList<>();
	
}