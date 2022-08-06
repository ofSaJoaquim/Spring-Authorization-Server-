package br.com.ofsajoaquim.authuser.api;


import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

import br.com.ofsajoaquim.authuser.domain.UserEntity;

public class UserRequest {
    @NotBlank
    private String name;
    @NotBlank
    private String email;
    @NotBlank
    private String password;
    @NotNull
    private UserEntity.Type type;

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

    public UserEntity.Type getType() {
        return type;
    }

    public void setType(UserEntity.Type type) {
        this.type = type;
    }

    public UserEntity toEntity() {
        return new UserEntity(
                this.name,
                this.email,
                this.password,
                this.type
        );
    }
}