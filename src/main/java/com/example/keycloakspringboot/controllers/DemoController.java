package com.example.keycloakspringboot.controllers;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.token.DefaultToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/v1/demo")
public class DemoController {


//    @PreAuthorize("hasRole('ROLE_USER') and #yourObject.field == authentication.principal.username")
//    public void authorizedMethod(YourObject yourObject) {
//        // Method logic for authorized users
//    }

//    @PostAuthorize("hasRole('ROLE_ADMIN') or returnObject.owner == authentication.principal.username")
//    public YourObject retrieveObject(int objectId) {
//        // Method logic to retrieve an object
//        return yourObject;
//    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
//    @RolesAllowed("USER")
    public String hello() {
        return "Hello from Spring and Keycloak";
    }

    @GetMapping("/hello2")
//    @PreAuthorize("hasRole('ADMIN')")
//    @RolesAllowed("ADMIN")
    public String hello2() {
        return "Hello from Spring and Keycloak from Admin";
    }
}
