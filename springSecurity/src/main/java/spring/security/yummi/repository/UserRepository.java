package spring.security.yummi.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.yummi.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    boolean existsByUsername(String username);

    UserEntity findByUsername(String username);

}
