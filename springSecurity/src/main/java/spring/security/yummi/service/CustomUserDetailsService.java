package spring.security.yummi.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import spring.security.yummi.dto.CustomUserDetails;
import spring.security.yummi.entity.UserEntity;
import spring.security.yummi.repository.UserRepository;

@Service
// userDetailsService를 구현해야한다
// spring security가 해당 위치로 요청을 보낸다
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /*
    spring security는 어떤 요청이 로그인요청인지 판단하는 방법은?
    
    스프링 시큐리티는 기본적으로 로그인 요청을 처리하는 기본 경로와 처리 방식을 제공한다. 
    SecurityConfig의 설정 중 loginProcessingUrl() 같은 커스터마이징 설정을 하지 않으면,
    스프링 시큐리티는 다음과 같은 기본 설정을 사용하여 로그인 요청을 처리한다.
    
    스프링 시큐리티의 기본 로그인 처리

    스프링 시큐리티는 /login 경로로 들어오는 POST 요청을 로그인 요청으로 간주한다.
    이 경로는 loginProcessingUrl()을 명시적으로 설정하지 않았을 때 사용된다.

    별도로 loginPage()를 설정하지 않았다면, 스프링 시큐리티는 내장된 기본 로그인 페이지를 제공한다.
    기본 페이지는 브라우저에서 /login으로 접근하면 자동으로 표시된다.

    요청에 포함된 username과 password를 자동으로 처리한다.
    내부적으로 UserDetailsService를 호출하여 username으로 사용자를 조회한다.
    조회된 사용자 정보와 요청에서 전달된 비밀번호를 비교한다.
    인증 성공 또는 실패를 처리한다.
    설정이 없을 때의 동작 흐름
    만약 커스터마이징 없이 스프링 시큐리티를 기본 설정으로 두면:
    
    /login 경로로 POST 요청이 들어오면 로그인 요청으로 판단한다.
    스프링 시큐리티가 요청의 username과 password를 추출한다.
    등록된 UserDetailsService를 호출하여 사용자 정보를 조회한다.
    조회된 사용자 정보와 요청에 포함된 비밀번호를 비교한다.
    인증 성공 시, 기본 성공 페이지(/)로 리다이렉트된다.
    실패 시 /login?error로 리다이렉트된다.

    여기서 유저 검증은 구현된 CustomUserDetails의 메소드들을 통해서 검증을 진행한다.

    loginProcessingUrl() 설정이 없어도, 스프링 시큐리티는 기본 경로(/login)를 통해 로그인 요청을 판단하고 처리할 수 있다.
     다만, 이 기본 설정을 변경하거나 커스터마이징해야 하는 경우(예: /customLoginProc 같은 경로 사용), loginProcessingUrl()을 명시적으로 설정해야 한다.
    
    설정이 없는 경우에도 동작은 가능하지만, 커스터마이징이 필요한 애플리케이션에서는 설정을 추가하는 것이 일반적이다.
    */

    // username 검증 로직
    @Override
                                        // spring security가 username을 받아서 검증한다
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserEntity findUser = userRepository.findByUsername(username);

        if(findUser != null){
            // 클래스를 만들어 UserDetails를 구현해야한다.
            return new CustomUserDetails(findUser);
        }

        return null;
    }
}
