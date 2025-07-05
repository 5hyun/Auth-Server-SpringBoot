# AuthServer-SpringBoot

## 프로젝트 개요
이 프로젝트는 Spring Boot 기반의 인증 및 권한 부여 서버입니다. 사용자 로그인, 회원가입, 토큰 갱신, 로그아웃 기능을 제공하며, JWT(JSON Web Token)를 사용하여 인증을 처리합니다.

## 프로젝트 버전
*   **Spring Boot:** 3.3.1
*   **Java:** 21

## 주요 라이브러리 및 기술 스택
*   **Spring Boot Starter Data JPA:** JPA(Java Persistence API)를 사용하여 데이터베이스와 상호작용합니다.
*   **Spring Boot Starter Security:** Spring Security를 사용하여 인증 및 권한 부여 기능을 구현합니다.
*   **Spring Boot Starter Validation:** `@Valid` 어노테이션을 사용하여 요청 데이터 유효성 검사를 수행합니다.
*   **Spring Boot Starter Web:** RESTful API를 구축하는 데 필요한 웹 기능을 제공합니다.
*   **Spring Boot Starter Data Redis:** Redis를 사용하여 토큰 관리 및 캐싱을 처리합니다.
*   **Lombok:** Getter, Setter, 생성자 등을 자동으로 생성하여 코드 작성을 줄여줍니다.
*   **MySQL Connector/J:** MySQL 데이터베이스와의 연결을 위한 JDBC 드라이버입니다.
*   **jjwt (Java JWT):** JWT(JSON Web Token) 생성 및 검증을 위한 라이브러리입니다.
*   **Springdoc OpenAPI UI:** API 문서를 자동으로 생성하고 시각화하는 Swagger UI를 제공합니다. (현재 2.5.0 버전 사용)

## 코드 설명

### 1. `AuthServerApplication.java`
*   Spring Boot 애플리케이션의 메인 진입점입니다.
*   `@SpringBootApplication` 어노테이션을 통해 Spring Boot 애플리케이션임을 선언합니다.
*   `@OpenAPIDefinition` 어노테이션을 추가하여 Swagger UI의 기본 정보를 설정합니다.

### 2. `config/SecurityConfig.java`
*   Spring Security 설정을 담당하는 클래스입니다.
*   `@EnableWebSecurity`를 통해 Spring Security를 활성화합니다.
*   `passwordEncoder()`: 비밀번호 암호화를 위한 `BCryptPasswordEncoder`를 빈으로 등록합니다.
*   `authenticationManager()`: 사용자 인증을 위한 `AuthenticationManager`를 설정합니다. `CustomUserDetailsService`를 사용하여 사용자 정보를 로드합니다.
*   `securityFilterChain()`: HTTP 요청에 대한 보안 필터 체인을 정의합니다.
    *   CSRF 보호를 비활성화합니다.
    *   세션 관리를 `STATELESS`로 설정하여 JWT 기반 인증에 적합하도록 합니다.
    *   `/api/users/login`, `/api/users/signup`, `/api/users/logout`, `/api/users/refresh`, `/swagger-ui/**`, `/v3/api-docs/**` 경로에 대한 접근을 `permitAll()`로 설정하여 인증 없이 접근 가능하도록 합니다.
    *   나머지 모든 요청은 `authenticated()`로 설정하여 인증된 사용자만 접근 가능하도록 합니다.
    *   `JwtAuthenticationFilter`를 `UsernamePasswordAuthenticationFilter` 이전에 추가하여 JWT 기반 인증을 처리합니다.

### 3. `config/RedisConfig.java`
*   Redis 관련 설정을 담당하는 클래스입니다. (내용은 제공되지 않았지만, RedisTemplate 등을 설정할 것으로 예상됩니다.)

### 4. `config/jwt/JwtAuthenticationFilter.java`
*   JWT 인증을 위한 커스텀 필터입니다.
*   요청 헤더에서 JWT 토큰을 추출하고 유효성을 검증합니다.
*   유효한 토큰인 경우, 토큰에서 사용자 정보를 추출하여 Spring Security의 `SecurityContextHolder`에 인증 정보를 설정합니다.

### 5. `config/jwt/JwtTokenProvider.java`
*   JWT 토큰 생성, 유효성 검증, 정보 추출 등의 기능을 제공하는 유틸리티 클래스입니다.
*   토큰의 서명 키, 만료 시간 등을 관리합니다.

### 6. `controller/UserController.java`
*   사용자 관련 API 엔드포인트를 정의하는 컨트롤러입니다.
*   회원가입, 로그인, 로그아웃, 토큰 갱신 등의 요청을 처리합니다.

### 7. `domain/User.java`
*   사용자 엔티티 클래스입니다.
*   데이터베이스의 `users` 테이블과 매핑됩니다.
*   사용자 ID, 비밀번호, 역할 등의 정보를 포함합니다.

### 8. `dto/` 패키지
*   API 요청 및 응답에 사용되는 DTO(Data Transfer Object) 클래스들을 포함합니다.
    *   `ErrorResponse.java`: 오류 응답 형식을 정의합니다.
    *   `LoginRequest.java`: 로그인 요청 데이터를 정의합니다.
    *   `SignUpRequest.java`: 회원가입 요청 데이터를 정의합니다.
    *   `TokenInfo.java`: JWT 토큰 정보를 정의합니다.

### 9. `exception/GlobalExceptionHandler.java`
*   애플리케이션 전역에서 발생하는 예외를 처리하는 클래스입니다.
*   `@RestControllerAdvice`를 사용하여 모든 `@RestController`에서 발생하는 예외를 중앙에서 처리합니다.
*   `MethodArgumentNotValidException` (유효성 검사 실패), `IllegalArgumentException` (비즈니스 로직 예외), `Exception` (일반 예외) 등을 처리하여 적절한 HTTP 상태 코드와 오류 응답을 반환합니다.

### 10. `repository/UserRepository.java`
*   사용자 데이터베이스 접근을 위한 JPA 리포지토리 인터페이스입니다.
*   `Spring Data JPA`의 기능을 활용하여 기본적인 CRUD(Create, Read, Update, Delete) 작업을 수행합니다.

### 11. `service/CustomUserDetailsService.java`
*   Spring Security에서 사용자 정보를 로드하는 `UserDetailsService` 인터페이스의 구현체입니다.
*   데이터베이스에서 사용자 정보를 조회하여 `UserDetails` 객체로 반환합니다.

### 12. `service/UserService.java`
*   사용자 관련 비즈니스 로직을 처리하는 서비스 클래스입니다.
*   회원가입, 로그인, 로그아웃, 토큰 갱신 등의 핵심 로직을 구현합니다.
