package com.example.AuthServer.controller;

import com.example.AuthServer.dto.LoginRequest;
import com.example.AuthServer.dto.SignUpRequest;
import com.example.AuthServer.dto.TokenInfo;
import com.example.AuthServer.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
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
        return ResponseEntity.ok("로그아웃 되었습니다.");
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenInfo> refresh(@RequestBody TokenInfo tokenInfo) {
        TokenInfo newTokens = userService.refreshTokens(tokenInfo.getRefreshToken());
        return ResponseEntity.ok(newTokens);
    }

    /**
     * Access Token의 유효성을 검증하는 엔드포인트입니다.
     * @param request HttpServletRequest 객체로부터 'Authorization' 헤더를 읽어옵니다.
     * @return 토큰이 유효하면 "유효한 토큰입니다." 메시지와 함께 200 OK, 그렇지 않으면 401 Unauthorized.
     */
    @GetMapping("/validate")
    public ResponseEntity<String> validateToken(HttpServletRequest request) {
        String accessToken = request.getHeader("Authorization");

        // 'Bearer ' 접두사 제거
        if (accessToken != null && accessToken.startsWith("Bearer ")) {
            accessToken = accessToken.substring(7);
        }

        if (userService.validateToken(accessToken)) {
            return ResponseEntity.ok("유효한 토큰입니다.");
        } else {
            return ResponseEntity.status(401).body("유효하지 않은 토큰입니다.");
        }
    }
}