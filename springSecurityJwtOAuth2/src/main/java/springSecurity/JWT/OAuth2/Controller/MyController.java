package springSecurity.JWT.OAuth2.Controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MyController {


    @GetMapping("/my")
    public String myP(){
        return "my";
    }

}
