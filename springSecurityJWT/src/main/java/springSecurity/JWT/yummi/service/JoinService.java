package springSecurity.JWT.yummi.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import springSecurity.JWT.yummi.dto.JoinDto;
import springSecurity.JWT.yummi.entity.UserEntity;
import springSecurity.JWT.yummi.repository.UserRepository;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Transactional
    public void joinProcess(JoinDto joinDto){

        String username = joinDto.getUsername();
        String password = joinDto.getPassword();

        boolean isExist = userRepository.existsByUsername(username);

        if(isExist){
            // 회원 가입 취소(이미 존재함)
            return ;
        }

        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setPassword(bCryptPasswordEncoder.encode(password));
        user.setRole("ROLE_ADMIN");
        userRepository.save(user);
    }

}
