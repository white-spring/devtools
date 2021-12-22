package com.white.dvt.core.exception;

import lombok.Getter;

/**
 * 错误异常
 *
 * @author whiteSpring
 */
public class ErrorException extends RuntimeException {

    @Getter
    private final String code;

    public ErrorException(String code) {
        super();
        this.code = code;
    }
}
