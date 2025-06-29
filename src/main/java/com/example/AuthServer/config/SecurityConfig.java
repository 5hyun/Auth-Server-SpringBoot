package com.example.AuthServer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCrypt 알고리즘을 사용하는 PasswordEncoder를 빈으로 등록합니다.
        // BCrypt는 현재 가장 널리 사용되는 안전한 해싱 알고리즘 중 하나입니다.
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // CSRF(Cross-Site Request Forgery) 보호를 비활성화합니다.
                // REST API 서버는 보통 세션을 사용하지 않으므로 CSRF 보호가 불필요합니다.
                .csrf(AbstractHttpConfigurer::disable)

                .authorizeHttpRequests(authorize -> authorize
                        // "/api/users/signup" 경로는 인증 없이 누구나 접근을 허용합니다.
                        .requestMatchers("/api/users/signup").permitAll()
                        // 그 외의 모든 요청은 인증된 사용자만 접근할 수 있습니다.
                        .anyRequest().authenticated()
                );

        return http.build();
    }
}