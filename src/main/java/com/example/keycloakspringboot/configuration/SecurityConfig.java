package com.example.keycloakspringboot.configuration;

import com.example.keycloakspringboot.converters.JwtAuthConverter;
import com.example.keycloakspringboot.propertes.SecurityPropertiesExtension;
import com.example.keycloakspringboot.role.permission.DomainAwarePermissionEvaluator;
import lombok.RequiredArgsConstructor;
import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootProperties;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.client.KeycloakClientRequestFactory;
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
import org.keycloak.adapters.springsecurity.management.HttpSessionManager;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Scope;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;


// Basic keycloak authentication
//@KeycloakConfiguration = @EnableWebSecurity + @Configuration
// .requestMatchers(HttpMethod.GET).hasRole("USER") = RolesAllow("USER")
//@EnableWebSecurity
@EnableMethodSecurity(jsr250Enabled = true)
@RequiredArgsConstructor
@KeycloakConfiguration
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
@EnableConfigurationProperties({ KeycloakSpringBootProperties.class, SecurityPropertiesExtension.class })
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
public class SecurityConfig {
    private final JwtAuthConverter jwtAuthConverter;
    private final DomainAwarePermissionEvaluator permissionEvaluator;
    private final ApplicationContext applicationContext;
    private final RoleHierarchy roleHierarchy;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authRequest -> authRequest
                        .requestMatchers("/api/*").authenticated()
                        .anyRequest().permitAll()
                )
                // default one is JwtAuthenticationConverter to convert jwt to AbstractAuthenticationToken
                // it usually did not convert correctly grant authorities of user from jwt
                // in this case we have to use alternative way
                // to map role on json of keycloak we can use CustomKeycloakAuthenticationProvider
                // or use jwtAuthConverter
                .oauth2ResourceServer(authResourceServer -> authResourceServer
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(jwtAuthConverter)
                        )
                )
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionAuthenticationStrategy(new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl()))
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                );

        return httpSecurity.build();
    }

//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) {
//        auth.authenticationProvider(getKeycloakAuthenticationProvider());
//    }

//    @Bean
//    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
//        return http.getSharedObject(AuthenticationManagerBuilder.class)
//                .authenticationProvider(getKeycloakAuthenticationProvider())
//                .build();
//    }

    @Bean
    public NullAuthenticatedSessionStrategy nullAuthenticatedSessionStrategy() {
        return new NullAuthenticatedSessionStrategy();
    }

    @Bean
    @ConditionalOnMissingBean(HttpSessionManager.class)
    protected HttpSessionManager httpSessionManager() {
        return new HttpSessionManager();
    }

    @Bean
    public KeycloakAuthenticationProvider keycloakAuthenticationProvider() {
        KeycloakAuthenticationProvider provider = new KeycloakAuthenticationProvider();
        provider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
        return provider;
    }


    /**
     * Use Keycloak configuration from properties / yaml
     *
     * @return
     */
    @Bean
    @Primary
    public KeycloakConfigResolver keycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

    /**
     * {@link KeycloakRestTemplate} configured to use {@link org.keycloak.representations.AccessToken} of current
     * user.
     *
     * @param requestFactory
     * @return
     */
    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public KeycloakRestTemplate keycloakRestTemplate(KeycloakClientRequestFactory requestFactory) {
        return new KeycloakRestTemplate(requestFactory);
    }

    // If not use default we can use a customization RoleResolvingGrantedAuthoritiesMapper
//    private KeycloakAuthenticationProvider getKeycloakAuthenticationProvider() {
////        KeycloakAuthenticationProvider keycloakAuthenticationProvider = new KeycloakAuthenticationProvider();
////        var mapper = new SimpleAuthorityMapper();
////        mapper.setConvertToUpperCase(true);
////        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(mapper);
////        return keycloakAuthenticationProvider;
//
//        SimpleAuthorityMapper grantedAuthorityMapper = new SimpleAuthorityMapper();
//        grantedAuthorityMapper.setConvertToUpperCase(true);
//
//        RoleResolvingGrantedAuthoritiesMapper resolvingMapper = new RoleResolvingGrantedAuthoritiesMapper(
//                roleHierarchy,
//                grantedAuthorityMapper);
////		RoleAppendingGrantedAuthoritiesMapper
//        return new CustomKeycloakAuthenticationProvider(resolvingMapper);
//    }

    @Bean
    protected MethodSecurityExpressionHandler createExpressionHandler() {
        DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
        expressionHandler.setPermissionEvaluator(permissionEvaluator);
        expressionHandler.setApplicationContext(applicationContext);
        return expressionHandler;
    }

}
