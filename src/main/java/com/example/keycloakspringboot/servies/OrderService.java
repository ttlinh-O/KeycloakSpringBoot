package com.example.keycloakspringboot.servies;

import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class OrderService {

    @PreAuthorize("hasPermission(null , 'create-order')")
    public String createOrder() {
        return UUID.randomUUID().toString();
    }
}
