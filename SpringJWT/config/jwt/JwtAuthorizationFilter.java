package com.jwt.SpringJWT.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.jwt.SpringJWT.config.auth.PrincipalDetails;
import com.jwt.SpringJWT.config.repository.UserRepository;
import com.jwt.SpringJWT.model.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//시큐리티가 filter를 가지고 있는데 그 필터 중에 BasicAuthenticationFilter라는 것이 있음
//권한이나 인증이 필요한 특정 주소를 요청하면 위 필터를 무조건 타게 되어있음
//만약 권한이 인증이 필요한 주소가 아니라면 이 필터를 안탐
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    //인증이나 권한이 필요한 주소요청이 있을 떄 해당 필터를 타게 됨
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
//        super.doFilterInternal(request, response, chain);
        System.out.println("인증이나 권한이 필요한 주소 요청 됨");

        String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);
        System.out.println("JWTHEADER : "+ jwtHeader);
        //header가 있는지 확인
        if(jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)){
            chain.doFilter(request, response);
            return;
        }
        //JWT 토큰을 검증해서 정상적인 사용자인지 확인!
        String jwtToken = request.getHeader("Authorization").replace(JwtProperties.TOKEN_PREFIX, ""); //Bearer로 시작하면, 그 부분을 ""으로 대체

        //JWT토큰의 시크릿 키 값인 cos를 가지고 있으면. jwtToken을 서명한다(?)
        String username =
                JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("username").asString();

        //서명이 정상적으로 됨
        if(username != null){
            System.out.println("username 정상");
            //Repository에서 username이 존재하는지 조회
            User userEntity = userRepository.findByUsername(username);

            //조회한 사용자 정보를 바탕으로 PrincipalDetails 생성
            //PrincipalDetails : Spring Security의 UserDetails 구현한 사용자 세부정보 객체
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            //JWT 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
            //들어가는 값은 user, password, role
            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
            //강제로 시큐리티 세션에 접근해 AUthentication 객체를 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }
    }
}
