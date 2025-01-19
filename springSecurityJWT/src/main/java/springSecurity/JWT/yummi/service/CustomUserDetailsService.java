package springSecurity.JWT.yummi.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import springSecurity.JWT.yummi.dto.CustomUserDetails;
import springSecurity.JWT.yummi.entity.UserEntity;
import springSecurity.JWT.yummi.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // UserDetailsService 인터페이스를 구현해야 해당 로직을 사용할 수 있다.
    // 다른 로직으로 인증을 시키고 싶다면 CustomAuthenticationProvider를
    // 오버라이딩해서 config를 통해 auth manager를 빌드하는 방식으로 구현할 수 있다
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity findUser = userRepository.findByUsername(username);

        if(findUser != null){
                        // 데이터를 넘겨주는 DTO이다.
                        // UserDetails의 구현체를 return 해야한다.
            return new CustomUserDetails(findUser);
        }

        return null;
    }

}
