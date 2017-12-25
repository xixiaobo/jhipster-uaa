package com.hcycom.jhipster.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.hcycom.jhipster.domain.Attribute_values;
import com.hcycom.jhipster.domain.Role;
import com.hcycom.jhipster.domain.User;
import com.hcycom.jhipster.service.mapper.Attribute_valuesMapper;
import com.hcycom.jhipster.service.mapper.RoleMapper;

/**
 * Authenticate a user from the database.
 */
@Component("userDetailsService")
public class DomainUserDetailsService implements UserDetailsService {

	private final Logger log = LoggerFactory.getLogger(DomainUserDetailsService.class);
	//
	// @Autowired
	// private UserService userSrevice;

	@Autowired
	private Attribute_valuesMapper valuesMapper;

	@Autowired
	private RoleMapper roleMapper;


	@Override
	@Transactional
	public UserDetails loadUserByUsername(final String login) {
		log.debug("Authenticating {}", login);
		String lowercaseLogin = login.toLowerCase(Locale.ENGLISH);
		// Optional<User> userFromDatabase =
		// userRepository.findOneWithAuthoritiesByLogin(lowercaseLogin);
		String password = null;
		String roles = null;
		String status = null;
		List<Attribute_values> list = valuesMapper.findUserByName("user", lowercaseLogin);
		if (list.size() == 0 || list == null) {
			throw new UsernameNotFoundException("User " + lowercaseLogin + " was not found in the " + "database");
		} else {
			for (Attribute_values attribute_values : list) {
				if (attribute_values.getAttribute_key().equals("password")) {
					password = attribute_values.getValue();
				} else if (attribute_values.getAttribute_key().equals("roles")) {
					roles = attribute_values.getValue();
				} else if (attribute_values.getAttribute_key().equals("status")) {
					status = attribute_values.getValue();
				}
			}
			if (status.equals("0")) {
				throw new UserNotActivatedException("User " + lowercaseLogin + " was not activated");
			} else {
				List<Role> rolelist = new ArrayList<Role>();
				String[] rolesids = roles.split(",");
				for (String rolesid : rolesids) {
					rolelist.add(roleMapper.getUsersAuthority(rolesid));
				}
				List<GrantedAuthority> grantedAuthorities = rolelist.stream()
						.map(role -> new SimpleGrantedAuthority(role.getRole_name())).collect(Collectors.toList());
				return new org.springframework.security.core.userdetails.User(lowercaseLogin, password,
						grantedAuthorities);
			}

		}

		// Optional<User> userFromDatabase
		// =userSrevice.findeUserByName(lowercaseLogin);
		// return userFromDatabase.map(users -> {
		// if (users.getStatus()==0) {
		// throw new UserNotActivatedException("User " + lowercaseLogin + " was
		// not activated");
		// }
		// List<GrantedAuthority> grantedAuthorities =
		// userSrevice.getUsersAuthority(users.getRoles());
		// return new
		// org.springframework.security.core.userdetails.User(lowercaseLogin,
		// users.getPassword(),
		// grantedAuthorities);
		// }).orElseThrow(() -> new UsernameNotFoundException("User " +
		// lowercaseLogin + " was not found in the " +
		// "database"));
	}
}
