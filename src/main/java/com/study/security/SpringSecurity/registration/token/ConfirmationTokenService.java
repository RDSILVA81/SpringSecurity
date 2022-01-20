package com.study.security.SpringSecurity.registration.token;

import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@AllArgsConstructor
public class ConfirmationTokenService {

    private final ConfirmationTokenRepository confirmationTokenRepository;

    public void saveConfirmationToken(ConfirmationToken token){
        confirmationTokenRepository.save(token);
    }

    public String confirmToken(String token){
        var confirmationToken =
                confirmationTokenRepository.findByToken(token)
                        .orElseThrow(()-> new IllegalStateException("Token not found"));
        if(confirmationToken.getConfirmedAt() != null){
            throw new IllegalStateException("Token already confirmed");
        }
        if(confirmationToken.getConfirmedAt().isBefore(LocalDateTime.now())){
            throw new IllegalStateException("Token expired");
        }
        confirmationTokenRepository.updateConfirmedToken(token, LocalDateTime.now());
        return null;
    }


}
