package com.example.keycloakspringboot.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("auth")
public class AuthenticationController {

    @GetMapping
    public String sayHello() {
        return "Hallo";
    }
}
