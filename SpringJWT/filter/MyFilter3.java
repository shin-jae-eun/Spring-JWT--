package com.jwt.SpringJWT.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

        //토큰을 cos로 만들었다고 가정하고!
        //id, pw가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답해준다.
        //요청할 때마다 header에 Authorzation에 value 값으로 토큰을 가져오겠져?
        //그때 토큰이 넘어오면 내가 만든 토큰이 맞는지만 검증하면 됨( RSA, HS256 )
public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        //로그 추가
        System.out.println("filter3 ====");
        // 만약, token을 검증하여, Controller에 접근 여부 설정!
        if (req.getMethod().equals("POST")) {
            String auth_header = req.getHeader("Authorization");

            if (auth_header.equals("secret")) {
                filterChain.doFilter(req, res);
            } else {
                PrintWriter writer = res.getWriter();
                writer.println("인증 안됨");
            }
        } else {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }
}