package springSecurity.JWT.OAuth2.dto;

import lombok.Data;

@Data
public class UserDTO {

    private String role;
    private String name;
    private String username;

}
