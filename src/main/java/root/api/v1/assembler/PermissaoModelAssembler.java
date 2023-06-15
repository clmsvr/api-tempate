package root.api.v1.assembler;

import java.util.List;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import root.api.v1.model.PermissaoModel;
import root.domain.model.Permissao;

@Component
public class PermissaoModelAssembler{
	
	@Autowired
	private ModelMapper modelMapper;
	
	public ModelMapper getModelMapper() {
		return modelMapper;
	}

	public PermissaoModel toModel(Permissao permissao) {
		
		return modelMapper.map(permissao, PermissaoModel.class);
	}
	
	public List<PermissaoModel> toCollectionModel(List<Permissao> list) 
	{
        return list.stream()
                .map(g -> toModel(g))
                .collect(Collectors.toList());
	}   
}