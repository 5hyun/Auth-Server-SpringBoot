package com.example.AuthServer.exception;

import com.example.AuthServer.dto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;
import java.util.stream.Collectors;

@RestControllerAdvice // 모든 @RestController에서 발생하는 예외를 처리하는 클래스임을 나타냅니다.
public class GlobalExceptionHandler {

    /**
     * @Valid 유효성 검사 실패 시 발생하는 예외를 처리합니다.
     * HTTP 400 Bad Request 상태 코드로 응답합니다.
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    protected ResponseEntity<ErrorResponse> handleMethodArgumentNotValid(MethodArgumentNotValidException e) {
        // 실패한 유효성 검사 각각의 에러 메시지를 리스트로 수집합니다.
        List<String> errorMessages = e.getBindingResult().getFieldErrors()
                .stream()
                .map(FieldError::getDefaultMessage)
                .collect(Collectors.toList());

        ErrorResponse errorResponse = ErrorResponse.builder()
                .code("INVALID_INPUT_VALUE")
                .message("입력값이 올바르지 않습니다.")
                .details(errorMessages)
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST);
    }

    /**
     * 이메일 중복 등 비즈니스 로직 상의 예외를 처리합니다.
     * HTTP 409 Conflict 상태 코드로 응답합니다.
     */
    @ExceptionHandler(IllegalArgumentException.class)
    protected ResponseEntity<ErrorResponse> handleIllegalArgument(IllegalArgumentException e) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .code("DUPLICATE_RESOURCE")
                .message(e.getMessage()) // Service에서 던진 메시지를 그대로 사용
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.CONFLICT);
    }

    /**
     * 위에서 처리하지 못한 모든 예외를 처리합니다.
     * HTTP 500 Internal Server Error 상태 코드로 응답합니다.
     */
    @ExceptionHandler(Exception.class)
    protected ResponseEntity<ErrorResponse> handleException(Exception e) {
        ErrorResponse errorResponse = ErrorResponse.builder()
                .code("INTERNAL_SERVER_ERROR")
                .message("서버 내부 오류가 발생했습니다.")
                .build();

        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}