package com.jwt.SpringJWT.config.auth;

import com.jwt.SpringJWT.config.repository.UserRepository;
import com.jwt.SpringJWT.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

//localhost:8000/login요청이 올 때 이 service가 동작한다.
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService의 loadUserByUsername()");
        User userEntity = userRepository.findByUsername(username);
        System.out.println("userentity" + userEntity);
        return new PrincipalDetails(userEntity);
    }
}
