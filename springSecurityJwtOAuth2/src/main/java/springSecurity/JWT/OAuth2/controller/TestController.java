package springSecurity.JWT.OAuth2.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class TestController {


    @GetMapping("/test")
    public String testP(){
        return "test";
    }

}
