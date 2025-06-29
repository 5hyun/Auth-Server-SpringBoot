package com.example.AuthServer.domain;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Getter
@NoArgsConstructor // 기본 생성자 추가
@Entity // 이 클래스가 데이터베이스 테이블과 매핑되는 엔티티 클래스임을 나타냅니다.
@Table(name = "users") // 데이터베이스에 'users'라는 이름의 테이블로 생성됩니다.
public class User {

    @Id // 이 필드가 테이블의 기본 키(Primary Key)임을 나타냅니다.
    @GeneratedValue(strategy = GenerationType.IDENTITY) // 기본 키 값이 데이터베이스에 의해 자동으로 생성되도록 합니다. (MySQL의 AUTO_INCREMENT)
    @Column(name = "id", updatable = false)
    private Long id;

    @Column(name = "email", nullable = false, unique = true) // 'email' 컬럼이며, null을 허용하지 않고 유일한 값이어야 함을 나타냅니다.
    private String email;

    @Column(name = "password", nullable = false) // 'password' 컬럼이며, null을 허용하지 않습니다.
    private String password;

    @Column(name = "name", nullable = false, length = 10)
    private String name;

    @Column(name = "nickName", nullable = false, unique = true, length = 10)
    private String nickName;

    @Column(name = "birth", nullable = false)
    private LocalDate birth;

    // Lombok의 @Builder를 사용하여 빌더 패턴으로 객체를 생성할 수 있게 합니다.
    // 생성자 위에 선언하면, 해당 생성자에 포함된 필드만 빌더에 포함됩니다.
    @Builder
    public User(String email, String password, String name, String nickName, LocalDate birth) {
        this.email = email;
        this.password = password;
        this.name = name;
        this.nickName = nickName;
        this.birth = birth;
    }
}