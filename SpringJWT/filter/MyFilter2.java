package com.jwt.SpringJWT.filter;

import javax.servlet.*;
import java.io.IOException;

public class MyFilter2 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        System.out.println("필터 2");
        chain.doFilter(servletRequest, servletResponse);
    }
}
