package com.example.keycloakspringboot.converters;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
@RequiredArgsConstructor
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    private final GrantedAuthoritiesMapper grantedAuthoritiesMapper;

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
//        var authorities = Stream.concat(jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
//                getExtractResourceAccessRoles(jwt).stream());
        Collection<GrantedAuthority> defaultAuthority = Optional.of(jwtGrantedAuthoritiesConverter).map(mapper -> mapper.convert(jwt)).orElse(Set.of());
        Collection<? extends GrantedAuthority> grantedAuthorities = grantedAuthoritiesMapper.mapAuthorities(getExtractResourceAccessRoles(jwt));
        var authorities = Stream.concat(defaultAuthority.stream(), grantedAuthorities.stream());
        return new JwtAuthenticationToken(
                jwt,
                authorities.collect(Collectors.toSet()),
                getPrincipleClaimName(jwt)
        );
    }

    private static String getPrincipleClaimName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB;
        if (Objects.nonNull(jwt.getClaim("preferred_username"))) {
            claimName = "preferred_username";
        }
        return claimName;
    }

    private Collection<? extends GrantedAuthority> getExtractResourceAccessRoles(Jwt jwt) {
        if (Objects.isNull(jwt.getClaim("realm_access"))) {
            return Set.of();
        }
        Map<String, Object> realmAccess = jwt.getClaim("realm_access");
        Collection<String> resourceRoles = (Collection<String>) realmAccess.get("roles");
        if (Objects.isNull(resourceRoles)) {
            return Set.of();
        }

        return resourceRoles
                .stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }
}
