package springSecurity.JWT.yummi.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Collection;
import java.util.Iterator;

@Controller
@RequiredArgsConstructor
@ResponseBody
public class MainController {

    @GetMapping("/")
    public String mainP(){

        // JWT는 stateless지만
        // JWTfilter를 통과한 순간 일시적으로 session을 만들기 때문에
        // 해당 메소드로 정보를 확인할 수 있다.
        String username = SecurityContextHolder.getContext().getAuthentication().getName();

        // role 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iter = authorities.iterator();
        GrantedAuthority auth = iter.next();
        String role = auth.getAuthority();

        return "mainController : " + username + " role : " + role;
    }
}
