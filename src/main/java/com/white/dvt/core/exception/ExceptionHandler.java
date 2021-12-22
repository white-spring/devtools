package com.white.dvt.core.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;

/**
 * 自定义异常处理，转换为自定义的返回类型
 *
 * @author whiteSpring
 */
@Slf4j
@ControllerAdvice
public class ExceptionHandler {

    @org.springframework.web.bind.annotation.ExceptionHandler(ErrorException.class)
    public ResponseEntity<ExceptionResponse> processFeignException(ErrorException exception) {
        //todo 需要转化成消息
        ExceptionResponse er = new ExceptionResponse(exception.getCode());
        return new ResponseEntity<>(er, HttpStatus.OK);
    }
}
