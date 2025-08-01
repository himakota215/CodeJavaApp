package net.codejava;
import java.util.List; 
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.core.annotation.AuthenticationPrincipal;



//Test change for Git hub

@Controller
public class AppController {
	@Autowired
	private UserRepository repo;
	@GetMapping("")
	public String viewHomePage() {
		return "index";
	} 
     @GetMapping("/register")
     public String showSignUpForm(Model model) {
    	 model.addAttribute("user",new User());
    	 return "index2";
     }
     @PostMapping("/process_register")
     public String processRegistration(User user) {
    	 BCryptPasswordEncoder encoder=new BCryptPasswordEncoder();
          String encodedPassword = encoder.encode(user.getPassword());
          user.setPassword(encodedPassword);
          
          
    	 repo.save(user);
    	 return "register_sucess";
     
     }
     @GetMapping("/list_users")
     public String viewUsersList(Model model, @AuthenticationPrincipal CustomerUserDetails loggedUser) {
         List<User> listUsers = repo.findAll();
         model.addAttribute("listUsers", listUsers);

         // Pass full name of the logged-in user to the view
         model.addAttribute("fullName", loggedUser.getFullName());

         return "users";
     }

          

}