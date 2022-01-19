package com.study.security.SpringSecurity.registration;

import org.springframework.stereotype.Service;

import java.util.function.Predicate;
import java.util.regex.Pattern;

@Service
public class EmailValidator implements Predicate<String> {

    private static final Pattern patter = Pattern.compile("^[A-Za-z0-9+_.-]+@(.+)$");

    @Override
    public boolean test(String email) {
        return patter.matcher(email).matches();
    }
}
