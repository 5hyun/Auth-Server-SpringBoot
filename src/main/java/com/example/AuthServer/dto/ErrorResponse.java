package com.example.AuthServer.dto;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
public class ErrorResponse {

    private final String code;
    private final String message;
    private final List<String> details;

    @Builder
    public ErrorResponse(String code, String message, List<String> details) {
        this.code = code;
        this.message = message;
        this.details = details;
    }
}