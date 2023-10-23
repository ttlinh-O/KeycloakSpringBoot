package com.example.keycloakspringboot.role.permission;

import com.example.keycloakspringboot.data.Order;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Set;

@Slf4j
@Component
@RequiredArgsConstructor
public class DomainAwarePermissionEvaluator implements PermissionEvaluator {
    private final PermissionResolver permissionResolver;
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        log.info("check permission '{}' for user '{}' for target '{}'", permission, authentication.getName(),
                targetDomainObject);
        Set<String> givenPermissions = permissionResolver.resolve(authentication);
        Set<String> requiredPermissions = toPermissions(permission);

        boolean permissionMatch = givenPermissions.containsAll(requiredPermissions);
        if (!permissionMatch) {
            log.debug("Insufficient permissions:\nRequired: {}\nGiven: {}", requiredPermissions, givenPermissions);
            return false;
        }

        // Delegate to bounded context specific permission evaluation...
        if ("place-order".equals(permission)) {
            Order order = (Order) targetDomainObject;
            if (order.getAmount() > 500) {
                return hasRole("ROLE_ADMIN", authentication);
            }
        }

        return true;
    }

    private Set<String> toPermissions(Object permissions) {
        if(permissions instanceof  String) {
            return Collections.singleton(permissions.toString());
        }

        // TODO deal with other forms of required permissions...
        return Collections.emptySet();
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        return hasPermission(authentication, new DomainObjectReference(targetId, targetType), permission);
    }

    @Value
    static class DomainObjectReference {
        private final Serializable targetId;
        private final String targetType;
    }

    private boolean hasRole(String role, Authentication auth) {
        if (auth == null || auth.getPrincipal() == null) {
            return false;
        }

        Collection<? extends  GrantedAuthority> authorities = auth.getAuthorities();
        return authorities.stream().anyMatch(ga -> role.equals(ga.getAuthority()));
    }
}
