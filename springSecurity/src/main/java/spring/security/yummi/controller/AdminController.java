package spring.security.yummi.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AdminController {

    @GetMapping("/admin")
    public String admin(){
        // config클래스를 통해 role ADMIN이 없다면 거부한다.
        // 로그인 설정을 해야 로그인 창이 뜨게 된다.
        return "admin";
    }

}
