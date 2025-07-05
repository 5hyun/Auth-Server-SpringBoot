package com.example.AuthServer.service;

import com.example.AuthServer.config.jwt.JwtTokenProvider;
import com.example.AuthServer.domain.User;
import com.example.AuthServer.dto.SignUpRequest;
import com.example.AuthServer.dto.TokenInfo;
import com.example.AuthServer.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTemplate<String, String> redisTemplate;

    @Transactional
    public Long signUp(SignUpRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("이미 사용 중인 이메일입니다.");
        }
        if (userRepository.findByNickName(request.getNickName()).isPresent()) {
            throw new IllegalArgumentException("이미 사용 중인 닉네임입니다.");
        }
        String encodedPassword = passwordEncoder.encode(request.getPassword());
        User user = User.builder()
                .email(request.getEmail())
                .password(encodedPassword)
                .name(request.getName())
                .nickName(request.getNickName())
                .birth(request.getBirth())
                .build();
        User savedUser = userRepository.save(user);
        return savedUser.getId();
    }

    @Transactional
    public TokenInfo login(String email, String password) {
        try {
            // 1. 사용자 인증을 위한 토큰 생성
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email, password);

            // 2. 실제 검증
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 3. 인증 정보를 기반으로 JWT 토큰 생성
            TokenInfo tokenInfo = jwtTokenProvider.generateToken(authentication);

            // 4. RefreshToken Redis 저장 (Key: RT:<email>, Value: refreshToken)
            redisTemplate.opsForValue().set("RT:" + authentication.getName(), tokenInfo.getRefreshToken(), jwtTokenProvider.getExpiration(tokenInfo.getRefreshToken()), TimeUnit.MILLISECONDS);

            return tokenInfo;
        } catch (AuthenticationException e) {
            // 4. 인증 실패 시 예외 처리
            throw new IllegalArgumentException("회원 정보를 찾을 수 없습니다.");
        }
    }

    @Transactional
    public void logout(HttpServletRequest request) {
        // 1. Request Header 에서 Access Token 추출
        String accessToken = jwtTokenProvider.resolveToken(request);

        // 2. Access Token 유효성 검사
        if (!StringUtils.hasText(accessToken) || !jwtTokenProvider.validateToken(accessToken)) {
            throw new IllegalArgumentException("유효하지 않은 토큰입니다.");
        }

        // 3. Access Token 에서 Authentication 객체 가져오기
        Authentication authentication = jwtTokenProvider.getAuthentication(accessToken);

        // 4. Access Token 의 남은 유효 시간 계산
        Long expiration = jwtTokenProvider.getExpiration(accessToken);

        // 5. Access Token 을 Redis 에 블랙리스트로 저장
        redisTemplate.opsForValue().set(accessToken, "logout", expiration, TimeUnit.MILLISECONDS);

        // 6. Refresh Token 삭제
        if (redisTemplate.opsForValue().get("RT:" + authentication.getName()) != null) {
            redisTemplate.delete("RT:" + authentication.getName());
        }
    }

    @Transactional
    public TokenInfo refreshTokens(String refreshToken) {
        // 1. Refresh Token 유효성 검사
        if (!jwtTokenProvider.validateToken(refreshToken)) {
            throw new IllegalArgumentException("유효하지 않은 Refresh Token 입니다.");
        }

        // 2. Refresh Token 에서 Authentication 객체 가져오기
        Authentication authentication;
        try {
            authentication = jwtTokenProvider.getAuthentication(refreshToken);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Refresh Token 에서 인증 정보를 가져올 수 없습니다: " + e.getMessage());
        }

        // 2-1. Authentication 객체에서 사용자 이름(이메일)이 null인 경우 처리
        if (authentication.getName() == null) {
            throw new IllegalArgumentException("Refresh Token 에 사용자 정보가 없습니다.");
        }

        // 3. Redis 에서 저장된 Refresh Token 가져오기
        String storedRefreshToken = redisTemplate.opsForValue().get("RT:" + authentication.getName());

        // 4. Redis 에 저장된 Refresh Token 이 없는 경우 또는 일치하지 않는 경우
        if (storedRefreshToken == null || !storedRefreshToken.equals(refreshToken)) {
            throw new IllegalArgumentException("Refresh Token 정보가 일치하지 않거나 만료되었습니다.");
        }

        // 5. 새로운 Access Token, Refresh Token 생성
        TokenInfo newTokens = jwtTokenProvider.generateToken(authentication);

        // 6. Redis Refresh Token 업데이트
        redisTemplate.opsForValue().set("RT:" + authentication.getName(), newTokens.getRefreshToken(), jwtTokenProvider.getExpiration(newTokens.getRefreshToken()), TimeUnit.MILLISECONDS);

        return newTokens;
    }
}