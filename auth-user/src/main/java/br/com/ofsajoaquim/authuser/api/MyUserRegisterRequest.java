package br.com.ofsajoaquim.authuser.api;

import javax.validation.constraints.NotBlank;

import br.com.ofsajoaquim.authuser.domain.UserEntity;

public class MyUserRegisterRequest {
    @NotBlank
    private String name;
    @NotBlank
    private String email;
    @NotBlank
    private String password;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public UserEntity toEntity() {
        return new UserEntity(
                this.name,
                this.email,
                this.password,
                UserEntity.Type.CLIENT
        );
    }
}