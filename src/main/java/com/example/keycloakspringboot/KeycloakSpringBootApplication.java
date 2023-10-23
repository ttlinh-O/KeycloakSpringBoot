package com.example.keycloakspringboot;

import com.example.keycloakspringboot.propertes.SecurityPropertiesExtension;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
public class KeycloakSpringBootApplication {

    public static void main(String[] args) {
        SpringApplication.run(KeycloakSpringBootApplication.class, args);
    }

}
