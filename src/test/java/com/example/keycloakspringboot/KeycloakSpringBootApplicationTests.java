package com.example.keycloakspringboot;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;

@SpringBootTest
class KeycloakSpringBootApplicationTests {

    @Test
    @WithMockUser(roles = {""})
    void contextLoads() {
    }

}
