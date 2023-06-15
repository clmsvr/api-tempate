package root.api.v1.assembler;

import java.util.List;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import root.api.v1.model.UsuarioModel;
import root.api.v1.model.input.UsuarioInputCreate;
import root.api.v1.model.input.UsuarioInputUpdate;
import root.domain.model.Usuario;

@Component
public class UsuarioModelAssembler {
	
	@Autowired
	private ModelMapper modelMapper;
		
	public ModelMapper getModelMapper() {
		return modelMapper;
	}
	
	public UsuarioModel toModel(Usuario usuario) {
		
		return modelMapper.map(usuario, UsuarioModel.class);
	}
	
    public List<UsuarioModel> toCollectionModel(List<Usuario> usuarios) {
        return usuarios.stream()
                .map(g -> toModel(g))
                .collect(Collectors.toList());
    }
	
    public Usuario toDomainObject(UsuarioInputCreate usuarioInput) {
        return modelMapper.map(usuarioInput, Usuario.class);
    }
    
    public Usuario toDomainObject(UsuarioInputUpdate usuarioInput) {
        return modelMapper.map(usuarioInput, Usuario.class);
    }    
    
}