package sv.edu.udb.InvestigacionDwf.service.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import sv.edu.udb.InvestigacionDwf.dto.LoginRequest;
import sv.edu.udb.InvestigacionDwf.dto.RegisterRequest;
import sv.edu.udb.InvestigacionDwf.exception.UserAlreadyExistException;
import sv.edu.udb.InvestigacionDwf.model.Role;
import sv.edu.udb.InvestigacionDwf.model.User;
import sv.edu.udb.InvestigacionDwf.repository.RoleRepository;
import sv.edu.udb.InvestigacionDwf.repository.UserRepository;
import sv.edu.udb.InvestigacionDwf.security.jwt.JwtUtils;
import sv.edu.udb.InvestigacionDwf.service.AuthService;

import java.util.Collections;

@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;

    public AuthServiceImpl(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder, JwtUtils jwtUtils) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtils = jwtUtils;
    }

    @Override
    public String register(RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.getName())) {
            logger.error("El usuario ya existe: {}", registerRequest.getName());
            throw new UserAlreadyExistException("El usuario ya existe");
        }

        // Obtener el rol por defecto (ROLE_USER) dinámicamente
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Rol ROLE_USER no encontrado"));

        User user = new User();
        user.setUsername(registerRequest.getName());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
        user.setEmail(registerRequest.getEmail());

        // Asignar el rol directamente al usuario
        user.setRole(userRole);

        // Generar JWT
        String token = jwtUtils.generateToken(user.getUsername(), "ROLE_USER");
        user.setToken(token); // Guardar el token en el usuario

        userRepository.save(user); // Persistir el usuario

        logger.info("Usuario registrado: {}", registerRequest.getName());

        return token; // Devolver el token generado
    }




    @Override
    public String login(LoginRequest loginRequest) {
        User user = userRepository.findByUsername(loginRequest.getEmail())
                .orElseThrow(() -> {
                    logger.error("Usuario no encontrado: {}", loginRequest.getEmail());
                    return new RuntimeException("Usuario no encontrado");
                });

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            logger.error("Credenciales inválidas para el usuario: {}", loginRequest.getEmail());
            throw new RuntimeException("Credenciales inválidas");
        }

        // Obtener el rol del usuario (ahora solo hay un rol)
        String role = user.getRole().getName();  // Acceder al rol directamente

        // Generar JWT
        String token = jwtUtils.generateToken(user.getUsername(), role);

        // Asignar el token al usuario
        user.setToken(token);
        userRepository.save(user); // Actualizar el token del usuario

        logger.info("Usuario autenticado exitosamente: {}", loginRequest.getEmail());

        return token; // Devolver el token generado
    }

}
