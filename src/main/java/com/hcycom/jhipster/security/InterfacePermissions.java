package com.hcycom.jhipster.security;

import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import com.hcycom.jhipster.service.mapper.InterfacePermissionsMapper;

@Component("InterfacePermissions")
public class InterfacePermissions {
	
	@Autowired
	private  InterfacePermissionsMapper interfacePermissionsMapper;
	
	public boolean hasPermission(Authentication authentication,String name){
		List<String> roles=interfacePermissionsMapper.getRoleByProduct(name);
		
		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        while(iterator.hasNext()){
            GrantedAuthority ga = iterator.next();
            if(ga.getAuthority().equals("ROLE_ADMIN")){
            	return true;
            }
            for (String role : roles) {
            	if(role.equals(ga.getAuthority())){
            		return true;
            	}
    		}    
        }
		return false;
	}
}
