package com.example.keycloakspringboot.controllers;

import com.example.keycloakspringboot.data.Order;
import com.example.keycloakspringboot.servies.OrderService;
import jakarta.annotation.security.RolesAllowed;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Slf4j
@RolesAllowed("ADMIN")
@RequestMapping("/api/orders")
@RestController
@RequiredArgsConstructor
public class OrderEndpoint {
    private final OrderService orderService;

    /**
     * Example for using fine grained application specific permissions
     *
     * @param order
     * @return
     */
    @PostMapping
//    @PreAuthorize("hasPermission(#order, 'create-order')")
    Map<String, Object> createOrder(@RequestBody Order order) {
        orderService.createOrder();
        Map<String, Object> map = new HashMap<>();
        map.put("orderId", UUID.randomUUID());
        return map;
    }

    /**
     * Example for using fine grained application specific permissions
     *
     * @param order
     * @return
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasPermission(#order, 'delete-order')")
    @ResponseStatus(HttpStatus.ACCEPTED)
    void deleteOrder(@PathVariable String id) {
        log.info("Delete order {}", id);
    }
}
