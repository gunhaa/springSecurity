package spring.security.yummi.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import spring.security.yummi.dto.JoinDto;
import spring.security.yummi.entity.UserEntity;
import spring.security.yummi.repository.UserRepository;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository joinRepository;

    // bean으로 등록 후 사용한다.
    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    @Transactional
    public void joinProcess(JoinDto joinDto){

        // 이미 동일한 username이 있을 경우 검증해야한다.
        // 1. entity에 unique 부여
        // 2. repo에 요청을 보내서 검증
        // 로직 필요하면 추가해야.. 정규식 등
        boolean userName = joinRepository.existsByUsername(joinDto.getUsername());

        if(userName){
            // logic..
        } else {
            // logic..
        }

        UserEntity user = new UserEntity();
        user.setUsername(joinDto.getUsername());

        user.setPassword(bCryptPasswordEncoder.encode(joinDto.getPassword()));

        // ROLE_역할로 넣어야한다.
//        user.setRole("ROLE_USER");
        user.setRole("ROLE_ADMIN");
        joinRepository.save(user);
    }

}
