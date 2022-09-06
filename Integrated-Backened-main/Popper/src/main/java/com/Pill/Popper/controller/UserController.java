package com.Pill.Popper.controller;

import java.util.List;

import javax.validation.Valid;

import com.Pill.Popper.dao.entity.User;
import com.Pill.Popper.dao.repository.RoleRepository;
import com.Pill.Popper.dao.repository.UserRepository;
import com.Pill.Popper.dao.security.JwtUtils;
import com.Pill.Popper.dao.service.UserService;
import com.Pill.Popper.exception.ResourceNotFoundException2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;



@RestController
@RequestMapping("/api/v1/")
public class UserController {
	@Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new JwtResponse(jwt,
                userDetails.getId(),
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!"));
        }

        // Create new user's account
        UserEntity user = new UserEntity( signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode( signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<RoleEntity> roles = new HashSet<>();

        if (strRoles == null) {
            RoleEntity userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        RoleEntity adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;

                    default:
                        RoleEntity userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	 	@GetMapping("/all")
	    public String allAccess() {
	        return "Public Content.";
	    }

	    @GetMapping("/user")
	    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
	    public String userAccess() {
	        return "User Content.";
	    }


	    @GetMapping("/admin")
	    @PreAuthorize("hasRole('ADMIN')")
	    public String adminAccess() {
	        return "Admin Board.";
	    }

    @Autowired
    private UserService userService;

    public UserController(UserService userService){
        super();
        this.userService = userService;
    }

    // get users

    @GetMapping("users")
    public List<User> getAllUsers(){
        return this.userService.getAllUsers();
    }

    // get user by id
    @GetMapping("users/{id}")
    public ResponseEntity<User> getUserById(@PathVariable("id") long userId) throws ResourceNotFoundException2 {
        return new ResponseEntity<User>(userService.getUserById(userId), HttpStatus.OK);
    }
    // save user
    @PostMapping("users")
    public User createUser(@RequestBody User user){
        return this.userService.save(user);
    }

    // update user
    @PutMapping("users/{id}")
    public ResponseEntity<User>updateUser(@PathVariable("id") long userId, @RequestBody User user) throws ResourceNotFoundException2 {

        return new ResponseEntity<User>(userService.updateUser(user, userId), HttpStatus.OK );
    }

    // delete user

    @DeleteMapping("users/{id}")
    public ResponseEntity<String> deleteUser(@PathVariable("id") long userId) throws ResourceNotFoundException2 {
        userService.deleteUserById(userId);

        return new ResponseEntity<String>("User details deleted successfully!", HttpStatus.OK);

    }

}