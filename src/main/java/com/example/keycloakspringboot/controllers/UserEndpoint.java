package com.example.keycloakspringboot.controllers;

import com.example.keycloakspringboot.role.permission.PermissionResolver;
import jakarta.annotation.security.RolesAllowed;
import lombok.RequiredArgsConstructor;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

@RolesAllowed("ADMIN")
@RequestMapping("/api/users")
@RestController
@RequiredArgsConstructor
public class UserEndpoint {
    private final PermissionResolver permissionResolver;

    /**
     * Dummy endpoint to return the resolved user information...
     *
     * @param token
     * @return
     */
    @GetMapping("/current")
    Object getUserInfo(JwtAuthenticationToken token) {
        Map<Object, Object> userInfo = new HashMap<>();
        userInfo.put("username", token.getName());
        userInfo.put("roles", token.getAuthorities().stream() //
                .map(GrantedAuthority::getAuthority) //
                .toList() //
        );
        userInfo.put("permissions", permissionResolver.resolve(token));

        return userInfo;
        }
}
