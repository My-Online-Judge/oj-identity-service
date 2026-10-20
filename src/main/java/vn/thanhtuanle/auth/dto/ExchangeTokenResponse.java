package vn.thanhtuanle.auth.dto;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class ExchangeTokenResponse {
    /**
     * The tokens never print, so no log line can carry one by accident. No {@code @Builder}: Lombok's builder
     * {@code toString} ignores {@code @ToString.Exclude}.
     */
    @ToString.Exclude
    String accessToken;
    Long expiresIn;
    @ToString.Exclude
    String refreshToken;
    String scope;
    String tokenType;
    /** Google's {@code id_token} (snake case, like the others): the identity of the user who signed in. */
    @ToString.Exclude
    String idToken;
}
