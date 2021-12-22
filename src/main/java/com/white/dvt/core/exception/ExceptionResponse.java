package com.white.dvt.core.exception;

import lombok.Getter;

/**
 * @author whiteSpring
 */
@Getter
public class ExceptionResponse {
    private Boolean failed;
    private String code;
    private String message;
    private String type;

    public ExceptionResponse(String message) {
        this.failed = true;
        this.message = message;
    }

}
