package sv.edu.udb.InvestigacionDwf.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import sv.edu.udb.InvestigacionDwf.dto.LoginRequest;
import sv.edu.udb.InvestigacionDwf.dto.RegisterRequest;
import sv.edu.udb.InvestigacionDwf.service.AuthService;

@Controller
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // Endpoint para mostrar el formulario de registro
    @GetMapping("/register")
    public String showRegisterForm() {
        return "register"; // Nombre de la plantilla Thymeleaf
    }

    // Endpoint para mostrar el formulario de login
    @GetMapping("/login")
    public String showLoginForm() {
        return "login"; // Nombre de la plantilla Thymeleaf
    }

    // Modifica el método POST de registro para manejar errores
    @PostMapping("/register")
    public String register(
            @RequestBody RegisterRequest registerRequest,
            BindingResult bindingResult,
            RedirectAttributes redirectAttrs
    ) {
        try {
            String token = authService.register(registerRequest);
            return "redirect:/auth/login?success=1"; // Redirige a login con mensaje de éxito
        } catch (Exception e) {
            redirectAttrs.addFlashAttribute("error", e.getMessage());
            return "redirect:/auth/register"; // Vuelve al formulario con error
        }
    }

    // Modifica el método POST de login para manejar errores
    @PostMapping("/login")
    public String login(
            @RequestBody LoginRequest loginRequest,
            RedirectAttributes redirectAttrs
    ) {
        try {
            String token = authService.login(loginRequest);
            return "redirect:/dashboard"; // Redirige a una página protegida
        } catch (Exception e) {
            redirectAttrs.addFlashAttribute("error", "Credenciales incorrectas");
            return "redirect:/auth/login"; // Vuelve al formulario con error
        }
    }
}
