package com.example.AuthServer.service;

import com.example.AuthServer.domain.User;
import com.example.AuthServer.dto.SignUpRequest;
import com.example.AuthServer.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor // final이 붙거나 @NotNull이 붙은 필드의 생성자를 자동으로 생성해주는 Lombok 어노테이션
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder; // 비밀번호 암호화를 위한 인코더

    @Transactional
    public Long signUp(SignUpRequest request) {
        // 이메일 중복 확인
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("이미 사용 중인 이메일입니다.");
        }

        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        // 사용자 정보 생성
        User user = User.builder()
                .email(request.getEmail())
                .password(encodedPassword) // 암호화된 비밀번호 사용
                .name(request.getName())
                .nickName(request.getNickName())
                .birth(request.getBirth())
                .build();

        // 사용자 정보 저장
        User savedUser = userRepository.save(user);
        return savedUser.getId();
    }
}