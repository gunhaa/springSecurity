package springSecurity.JWT.yummi.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import springSecurity.JWT.yummi.jwt.LoginFilter;

@Configuration
// springSecurity 설정임을 알림
@EnableWebSecurity
public class SecurityConfig {

    // 버전별로 설정 방법이 다르니 알아두어야한다
    // 해당 방법은 6.xx version의 설정 방법

    // 비밀번호를 hash로 암호화시키기 위해서
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    /*
     Spring이 AuthenticationConfiguration 객체를 자동으로 생성하여 SecurityConfig 클래스의 생성자로 주입한다.
    이 과정은 Spring 컨테이너의 의존성 주입에 의해 이루어진다.
    AuthenticationConfiguration은 Spring Security에서 제공하는 클래스이며, 기본적으로 Spring Context에 의해 관리되는 Bean이다.
    */
    private final AuthenticationConfiguration authenticationConfiguration;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration) {
        this.authenticationConfiguration = authenticationConfiguration;
    }

    //AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // 설정에 대한 세부 설명은 springSecurity의 SecurityConfig에 있다.

        // csrf disable
        // session이 stateless해서 보안을 강화하지 않아도 괜찮다.
        http.csrf((auth)->auth.disable());

        //Form 로그인 방식 disable
        http.formLogin((auth) -> auth.disable());

        // http basic 인증 disable
        http.httpBasic((auth) -> auth.disable());

        // 경로별 인가 작업
        http.authorizeHttpRequests((auth) ->
                auth.requestMatchers("/login", "/", "/join").permitAll()
                        .requestMatchers("/admin").hasRole("ADMIN")
                        // 다른 요청들에 대해서는, 로그인한 사용자만 접근 할 수 있게한다.
                        .anyRequest().authenticated());

        // 세션 설정
        // 가장 중요하다, 세션 STATELESS 설정이 필수
        http.sessionManagement((session) ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 필터 등록
        // UsernamePasswordAuthenticationFilter를 LoginFilter로 대체하는 설정
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration)), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

}
