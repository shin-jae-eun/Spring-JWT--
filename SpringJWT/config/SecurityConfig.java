package com.jwt.SpringJWT.config;

import com.jwt.SpringJWT.config.jwt.JwtAuthenticationFilter;
import com.jwt.SpringJWT.config.jwt.JwtAuthorizationFilter;
import com.jwt.SpringJWT.config.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    protected final CorsFilter corsFilter;
    private final UserRepository userRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션 없는 상태로 만들겠다.
        .and()
                .addFilter(corsFilter) //@CrossOrigin는 인증이 없을때만 사용 가능함!, 인증이 필요할 땐 필터에 등록해야한다
                .formLogin().disable()
                .httpBasic().disable()
                .addFilter(new JwtAuthenticationFilter(authenticationManager())) //AuthenticationManager를 파라미터로 꼭 넣어줘야함!!
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository)) //AuthenticationManager를 파라미터로 꼭 넣어줘야함!!
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
