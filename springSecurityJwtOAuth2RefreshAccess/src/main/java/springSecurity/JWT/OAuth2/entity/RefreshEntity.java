package springSecurity.JWT.OAuth2.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
public class RefreshEntity {

    @GeneratedValue
    @Id
    private Long id;

    // 하나의 유저가 여러개의 토큰을 발급 받을 수 있다. 유니크 불가능
    private String username;
    private String refresh;
    private String expiration;

}
