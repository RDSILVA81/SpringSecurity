package com.study.security.SpringSecurity.appuser;

import lombok.AllArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AppUserService implements UserDetailsService {

    private final AppUserRepository appUserRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final static String USER_NOT_FOUND_MSG = "User with email %s not found";

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return appUserRepository.findByEmail(email)
                .orElseThrow(()-> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG,email)));
    }

    public String signUpUser(AppUser user){
       var exist =  appUserRepository.findByEmail(user.getEmail()).isPresent();
       if(exist){
           throw new IllegalStateException("Email already exist.");
       }

       var encodedPassword = passwordEncoder.encode(user.getPassword());
       user.setPassword(encodedPassword);

       appUserRepository.save(user);

        return "";
    }
}
