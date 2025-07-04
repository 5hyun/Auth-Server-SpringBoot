package com.example.AuthServer.service;

import com.example.AuthServer.config.jwt.JwtTokenProvider;
import com.example.AuthServer.domain.User;
import com.example.AuthServer.dto.SignUpRequest;
import com.example.AuthServer.dto.TokenInfo;
import com.example.AuthServer.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;

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
            return jwtTokenProvider.generateToken(authentication);
        } catch (AuthenticationException e) {
            // 4. 인증 실패 시 예외 처리
            throw new IllegalArgumentException("회원 정보를 찾을 수 없습니다.");
        }
    }
}