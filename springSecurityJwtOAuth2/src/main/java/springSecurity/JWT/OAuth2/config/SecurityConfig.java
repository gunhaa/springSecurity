package springSecurity.JWT.OAuth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
// spring security가 bean을 찾을 수 있도록 한다
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{

        //csrf disable
        http.csrf((auth)-> auth.disable());

        //form 로그인 disable
        http.formLogin((auth)-> auth.disable());

        // httpBasic
        http.httpBasic((auth)->auth.disable());

        // 경로 별 인가작업
        http.authorizeHttpRequests((auth)->
                auth.requestMatchers("/").permitAll()
                        .anyRequest().authenticated()
        );

        // 세션 설정 : STATELESS
        // 세션을 비활성화시켜 인증 상태를 세션에 저장하지 않게하는 설정
        http.sessionManagement((session) ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        return http.build();
    }
}
