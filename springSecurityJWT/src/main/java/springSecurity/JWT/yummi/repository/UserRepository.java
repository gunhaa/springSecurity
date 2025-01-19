package springSecurity.JWT.yummi.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import springSecurity.JWT.yummi.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    boolean existsByUsername(String username);

    UserEntity findByUsername(String username);

}
