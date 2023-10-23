package com.example.keycloakspringboot.propertes;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@ConfigurationProperties(prefix = "security.authz")
public class SecurityPropertiesExtension {
    Map<String, List<String>> roleHierarchy = new HashMap<>();
    Map<String, List<String>> permissions = new HashMap<>();
}
