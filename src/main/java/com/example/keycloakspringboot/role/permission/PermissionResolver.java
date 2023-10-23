package com.example.keycloakspringboot.role.permission;

import org.springframework.security.core.Authentication;

import java.util.Set;

public interface PermissionResolver {
    Set<String> resolve(Authentication authentication);
}
