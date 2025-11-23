package org.carlosacademic.keycloackplayground.config;

import org.carlosacademic.keycloackplayground.jwt.JwtTokenConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtTokenConverter jwtTokenConverter;

    public SecurityConfig(JwtTokenConverter jwtTokenConverter) {
        this.jwtTokenConverter = jwtTokenConverter;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(req ->
                        req.requestMatchers("/health").permitAll())
                .authorizeHttpRequests(req -> {
                    req.requestMatchers("/hello/admin").hasAnyRole("admin-client-role");
                    req.requestMatchers("/hello/user").hasAnyRole("user-client-role", "admin-client-role");
                })
                .authorizeHttpRequests(req ->
                        req.anyRequest().authenticated())
                .oauth2ResourceServer(oauth ->
                        oauth.jwt(jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwtTokenConverter)))
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .build();
    }
}
