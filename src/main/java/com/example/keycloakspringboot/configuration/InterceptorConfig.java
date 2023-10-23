package com.example.keycloakspringboot.configuration;

import com.example.keycloakspringboot.Interceptor.CustomInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class InterceptorConfig implements WebMvcConfigurer {
    @Autowired
    private CustomInterceptor customInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(customInterceptor).addPathPatterns("/**")
                .addPathPatterns("/api/**") // Intercept requests starting with '/api/'
                .excludePathPatterns("/api/public/**") // Exclude requests starting with '/api/public/'
                .order(1); // Set the order of execution, if you have multiple interceptors
    }
}
