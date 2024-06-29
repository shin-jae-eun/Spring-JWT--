package com.jwt.SpringJWT.controller;

import com.jwt.SpringJWT.config.auth.PrincipalDetails;
import com.jwt.SpringJWT.config.repository.UserRepository;
import com.jwt.SpringJWT.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    @GetMapping("home")
    public String home(){
        return "<h1>home</h1>";
    }

    @PostMapping("token")
    public String token(){
        return "<h1>token</h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user) {
        //로그 추가
        System.out.println("receive? " + user);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "회원가입완료";
    }

    //user 권한만 접근 가능
    @GetMapping("/api/v1/user")
    public String user(Authentication authentication){
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principalDetails = " + principalDetails.getUsername());
        return "user";
    }

    //admin, manager 권한만 접근 가능
    @GetMapping("/api/v1/manager")
    public String manager(){
        return "manager";
    }


    //admin만 접근가능
    @GetMapping("/api/v1/admin")
    public String admin(){
        return "admin";
    }
}
