package vn.thanhtuanle.auth.dto;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.FieldDefaults;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class ExchangeTokenResponse {
    /** The tokens never print, so no log line can carry one by accident. */
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
