package com.example.keycloakspringboot.provider;

import lombok.RequiredArgsConstructor;
import org.keycloak.adapters.springsecurity.account.KeycloakRole;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@RequiredArgsConstructor
public class CustomKeycloakAuthenticationProvider extends KeycloakAuthenticationProvider {
    private final GrantedAuthoritiesMapper grantedAuthoritiesMapper;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) authentication;

        Collection<? extends GrantedAuthority> keycloakAuthorities = mapAuthorities(addKeycloakRoles(token));
        Collection<? extends GrantedAuthority> grantedAuthorities = addUserSpecificAuthorities(authentication,
                keycloakAuthorities);

        return new KeycloakAuthenticationToken(token.getAccount(), token.isInteractive(), grantedAuthorities);
    }

    protected Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        return grantedAuthoritiesMapper != null ? grantedAuthoritiesMapper.mapAuthorities(authorities) : authorities;
    }

    protected Collection<? extends GrantedAuthority> addKeycloakRoles(KeycloakAuthenticationToken token) {
        Collection<GrantedAuthority> keycloakRoles = new ArrayList<>();
        for (String role : token.getAccount().getRoles()) {
            keycloakRoles.add(new KeycloakRole(role));
        }

        return keycloakRoles;
    }

    protected Collection<? extends GrantedAuthority> addUserSpecificAuthorities(
            Authentication authentication,
            Collection<? extends GrantedAuthority> authorities
    ) {

        // potentially add user specific authentication, lookup from internal database
        // etc...

        List<GrantedAuthority> result = new ArrayList<>(authorities);
        if ("demo".equals(authentication.getName())) {
            result.add(new SimpleGrantedAuthority("ROLE_ORDER_DISPATCHER"));
        }

        return result;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return KeycloakAuthenticationToken.class.isAssignableFrom(aClass);
    }
}
