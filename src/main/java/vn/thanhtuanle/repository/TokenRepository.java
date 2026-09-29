package vn.thanhtuanle.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import vn.thanhtuanle.common.enums.TokenType;
import vn.thanhtuanle.entity.Token;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface TokenRepository extends JpaRepository<Token, UUID> {
    @Query(value = """
            select t from Token t inner join User u\s
            on t.user.id = u.id\s
            where u.id = :id and (t.expired = false or t.revoked = false)\s
            """)
    List<Token> findAllValidTokenByUser(UUID userId);

    Optional<Token> findByToken(String token);

    void deleteAllByUserId(UUID userId);

    void deleteAllByUserIdAndTokenType(UUID userId, TokenType tokenType);
}
