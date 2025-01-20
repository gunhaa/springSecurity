package springSecurity.JWT.OAuth2.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import springSecurity.JWT.OAuth2.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    UserEntity findByUsername(String username);

}
