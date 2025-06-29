package com.example.AuthServer.repository;

import com.example.AuthServer.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

// JpaRepository를 상속받습니다. 제네릭 타입으로 <엔티티 클래스, 기본 키 타입>을 지정합니다.
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Spring Data JPA는 메소드 이름 규칙에 따라 쿼리를 자동으로 생성합니다.
     * 'findByEmail'은 'email' 컬럼을 기준으로 사용자를 찾는 쿼리를 생성합니다.
     * 조회 결과가 없을 수도 있으므로, Null-safe한 처리를 위해 Optional<User> 타입으로 반환받습니다.
     */
    Optional<User> findByEmail(String email);
}