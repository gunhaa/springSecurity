package springSecurity.JWT.OAuth2.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import springSecurity.JWT.OAuth2.OAuth2.CustomSuccessHandler;
import springSecurity.JWT.OAuth2.jwt.JwtFilter;
import springSecurity.JWT.OAuth2.jwt.JwtUtil;
import springSecurity.JWT.OAuth2.service.CustomOAuth2UserService;

import java.util.Collections;

@Configuration
// spring security가 bean을 찾을 수 있도록 한다
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;
    private final JwtUtil jwtUtil;

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
                auth.requestMatchers("/my").hasAuthority("ROLE_USER")
                        .anyRequest().permitAll()
        );
//        http.authorizeHttpRequests((auth) -> auth
//                        .requestMatchers("/", "/oauth2/**", "/login/**", "/test").permitAll()
//                        .anyRequest().authenticated());


        // jwtFilter를 UsernamePasswordAuthenticationFilter 이전에 추가한다.

        /*
        필터 위치에 따라 OAuth2 인증을 진행하는 필터보다 JWTFilter가 앞에 존재하는 경우 아래와 같은 오류가 발생할 수 있다.
        재로그인
        JWT 만료 → 거절
        OAuth2 로그인 실패 → 재요청
        무한 루프
        */
        http.addFilterBefore(new JwtFilter(jwtUtil), OAuth2LoginAuthenticationFilter.class);

        // 세션 설정 : STATELESS
        // 세션을 비활성화시켜 인증 상태를 세션에 저장하지 않게하는 설정
        http.sessionManagement((session) ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // oauth2 사용 설정
        http.oauth2Login((oauth2) ->
                //로그인이 필요한 페이지를 들어갈때 리다이렉션 시키는 위치
                oauth2.loginPage("/login")
                        .userInfoEndpoint((userInfoEndpointConfig) ->
                        // oauth2 userservice에 커스텀 서비스 등록
                        userInfoEndpointConfig.userService(customOAuth2UserService))
                        // OAuth 로그인시 성공시 할 작업
                        .successHandler(customSuccessHandler)
                );

        // cors 설정
        // front랑 포트번호가 다르다면 필요하다
        http.cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                        CorsConfiguration configuration = new CorsConfiguration();

                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        configuration.setAllowCredentials(true);
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);

                        configuration.setExposedHeaders(Collections.singletonList("Set-Cookie"));
                        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

                        return configuration;
                    }}
        ));
        
        return http.build();
    }
}
