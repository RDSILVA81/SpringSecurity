package com.study.security.SpringSecurity.registration;

import com.study.security.SpringSecurity.appuser.AppUser;
import com.study.security.SpringSecurity.appuser.AppUserRole;
import com.study.security.SpringSecurity.appuser.AppUserService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class RegistrationService {

    private final EmailValidator emailValidator;
    private final AppUserService appUserService;

    public String register(RegistrationRequest request) {
        var isValidEmail = emailValidator.test(request.getEmail());
        if(!isValidEmail){
            throw new IllegalArgumentException(String.format("Email not valid '%s' ", request.getEmail()));
        }
        return appUserService.signUpUser(new AppUser(
                request.getFirstName(),
                request.getLastName(),
                request.getEmail(),
                request.getPassword(),
                AppUserRole.USER

        ));
    }
}
