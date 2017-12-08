package com.hcycom.jhipster.security;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.hcycom.jhipster.domain.User;
import com.hcycom.jhipster.service.UserService;

/**
 * Authenticate a user from the database.
 */
@Component("userDetailsService")
public class DomainUserDetailsService implements UserDetailsService {

    private final Logger log = LoggerFactory.getLogger(DomainUserDetailsService.class);
    
    @Autowired
    private UserService userSrevice;

//    private final UserService userSrevice;
//
//    public DomainUserDetailsService(UserService userSrevice) {
//        this.userSrevice = userSrevice;
//    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(final String login) {
        log.debug("Authenticating {}", login);
        String lowercaseLogin = login.toLowerCase(Locale.ENGLISH);
//        Optional<User> userFromDatabase = userRepository.findOneWithAuthoritiesByLogin(lowercaseLogin);
        Optional<User> userFromDatabase =userSrevice.findeUserByName(lowercaseLogin);
        return userFromDatabase.map(users -> {
        	 if (users.getStatus()==0) {
                 throw new UserNotActivatedException("User " + lowercaseLogin + " was not activated");
             }
            List<GrantedAuthority> grantedAuthorities = userSrevice.getUsersAuthority(users.getRoles());
            return new org.springframework.security.core.userdetails.User(lowercaseLogin,
                users.getPassword(),
                grantedAuthorities);
        }).orElseThrow(() -> new UsernameNotFoundException("User " + lowercaseLogin + " was not found in the " +
        "database"));
    }
}
