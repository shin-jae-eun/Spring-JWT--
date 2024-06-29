package com.jwt.SpringJWT.config.jwt;

public interface JwtProperties {
    String SECRET = "cos"; //우리 서버만 알고 있는 비밀 값
    int EXPIRATION_TIME = 60000 * 10;  // 만료 시간
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";
}
