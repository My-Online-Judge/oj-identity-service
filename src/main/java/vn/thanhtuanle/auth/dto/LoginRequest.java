package vn.thanhtuanle.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class LoginRequest {

    /** At most the audit's column: a longer one would also make the limiter's Redis keys as long as the client likes. */
    @NotBlank(message = "Username is required")
    @Size(max = 64, message = "Username must be at most 64 characters")
    private String username;

    @NotBlank(message = "Password is required")
    private String password;
}
