package com.jwt.SpringJWT.config.jwt;

import java.util.Date;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.jwt.SpringJWT.config.auth.PrincipalDetails;
import com.jwt.SpringJWT.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 이미 있음!
// /login으로 요청해서 username, password를 post로 전송하면 이 필터가 원래 동작했었음.
//그러나 지금 이 필터가 동작을 안하는 이유는 formlogin을 disable했기 때문.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    //id, pw 확인해서 정상인지 확인
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JWT AuthenticationFilter : 로그인 시도중");
        //1. request에 username, password를 받아서
        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while((input = br.readLine())!= null){
//                System.out.println(input);
//            }
//            System.out.println(request.getInputStream().toString()); //stream안에 username와 id ..이 담겨있음
            ObjectMapper om = new ObjectMapper(); //ObjectMapper가 **<json>** 데이터를 알아서 파싱해줌
            User user = om.readValue(request.getInputStream(), User.class); //user model에 알아서 파싱해준다 완전 GOOOD!!
            System.out.println(user); //잘 파싱된 것을 확인함.

            //2. user model token화 하기(원래 자동으로 해주는데 우리가 Filter 구현한 거라서 해줘야함)
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //3. PrincipalDetailsService의 loadUserByUsername()함수가 실행됨
            //loadUserByUsername 함수가 실행된 후 정상이면 authentication이 리턴됨
            // 즉 DB에 있는 username과 password가 일치한다는 뜻.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료" + principalDetails.getUser().getUsername()); //꺼냈을 때 값이 있으면 로그인이 정상적으로 되었다는 뜻

            //authentication 객체가 session 영역에 저장을 해야하는데 그 방법이 return을 해주면 됨
            //리턴을 해주는 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는 것!!
            //굳이 jwt 토큰을 사용하면서 세션을 만들 이유가 없.지.만, 단지 권한 처리 때문에 sessin을 넣어 주는 것이다.
            return authentication; // 이 값이 세션에 저장됨

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // attempAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication이 실행됨
    // 이때 jwt 토큰을 만들어서 request 요청한 사용자에게 jwt 토큰을 response해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증 완료!!");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal(); //authResult이 Authentication의 객체

        //RSA 방식은 아니고 Hash암호 방식
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME)) //10분
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET)); //server만 알고있는 secret 값

        response.addHeader("Authorization", JwtProperties.TOKEN_PREFIX+jwtToken);


//        super.successfulAuthentication(request, response, chain, authResult);
    }
}
