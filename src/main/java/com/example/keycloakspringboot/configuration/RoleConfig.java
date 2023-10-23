package com.example.keycloakspringboot.configuration;

import com.example.keycloakspringboot.propertes.SecurityPropertiesExtension;
import com.example.keycloakspringboot.role.RoleResolvingGrantedAuthoritiesMapper;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyUtils;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;

@Configuration
@AllArgsConstructor
public class RoleConfig {
    private final SecurityPropertiesExtension securityPropertiesExtension;

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy(RoleHierarchyUtils.roleHierarchyFromMap(securityPropertiesExtension.getRoleHierarchy()));
        return roleHierarchy;
    }

    @Bean
    public GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        SimpleAuthorityMapper grantedAuthorityMapper = new SimpleAuthorityMapper();
        grantedAuthorityMapper.setConvertToUpperCase(true);

        return new RoleResolvingGrantedAuthoritiesMapper(
                roleHierarchy(),
                grantedAuthorityMapper);
    }
}
