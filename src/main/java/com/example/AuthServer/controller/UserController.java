package com.example.AuthServer.controller;

import com.example.AuthServer.dto.LoginRequest;
import com.example.AuthServer.dto.SignUpRequest;
import com.example.AuthServer.dto.TokenInfo;
import com.example.AuthServer.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public ResponseEntity<String> signUp(@Valid @RequestBody SignUpRequest request) {
        Long userId = userService.signUp(request);
        return ResponseEntity.ok("회원가입이 성공적으로 완료되었습니다. 사용자 ID: " + userId);
    }

    @PostMapping("/login")
    public ResponseEntity<TokenInfo> login(@RequestBody LoginRequest loginRequest) {
        TokenInfo tokenInfo = userService.login(loginRequest.getEmail(), loginRequest.getPassword());
        return ResponseEntity.ok(tokenInfo);
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        userService.logout(request);
        return ResponseEntity.ok("로그아웃되었습니다.");
    }
}