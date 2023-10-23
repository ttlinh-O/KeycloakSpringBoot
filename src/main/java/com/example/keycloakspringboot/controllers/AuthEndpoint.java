package com.example.keycloakspringboot.controllers;

import jakarta.servlet.http.HttpSession;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RequestMapping("/api/auth")
@RestController
public class AuthEndpoint {
    @GetMapping
    Map<String, Object> getToken(HttpSession session) {
        return Collections.singletonMap("session", session.getId());
    }
}
