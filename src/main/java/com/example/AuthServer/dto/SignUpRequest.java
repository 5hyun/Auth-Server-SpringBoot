package com.example.AuthServer.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
@Builder
public class SignUpRequest {

    @NotBlank(message = "이메일은 필수 입력 값입니다.")
    @Email(message = "이메일 형식이 올바르지 않습니다.")
    private String email;

    /**
     * User 엔티티의 password 필드의 length=30 제약조건에 맞춰
     * 최소 8자, 최대 30자로 제한합니다.
     */
    @NotBlank(message = "비밀번호는 필수 입력 값입니다.")
    @Size(min = 8, max = 30, message = "비밀번호는 8자 이상 30자 이하이어야 합니다.")
    private String password;

    /**
     * User 엔티티의 name 필드의 length=10 제약조건에 맞춰
     * 최대 10자로 제한합니다.
     */
    @NotBlank(message = "이름은 필수 입력 값입니다.")
    @Size(max = 10, message = "이름은 10자를 넘을 수 없습니다.")
    private String name;

    /**
     * User 엔티티의 nickName 필드의 length=10 제약조건에 맞춰
     * 최대 10자로 제한합니다.
     */
    @NotBlank(message = "닉네임은 필수 입력 값입니다.")
    @Size(max = 10, message = "닉네임은 10자를 넘을 수 없습니다.")
    private String nickName;

    @NotNull(message = "생년월일은 필수 입력 값입니다.")
    private LocalDate birth;
}