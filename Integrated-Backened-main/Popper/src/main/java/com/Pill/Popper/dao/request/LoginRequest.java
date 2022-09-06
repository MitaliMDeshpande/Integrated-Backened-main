package com.Pill.Popper.dao.request;

import javax.validation.constraints.NotBlank;

public class LoginRequest {
    @lombok.Setter
    @lombok.Getter
    @NotBlank
    private String username;

    @NotBlank
    private String password;

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
