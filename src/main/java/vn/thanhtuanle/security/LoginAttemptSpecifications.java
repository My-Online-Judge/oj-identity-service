package vn.thanhtuanle.security;

import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;
import vn.thanhtuanle.entity.LoginAttempt;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public final class LoginAttemptSpecifications {

    private LoginAttemptSpecifications() {
    }

    public static Specification<LoginAttempt> filter(String ip, String username, Boolean success,
                                                     LocalDate createdFrom, LocalDate createdTo) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (ip != null && !ip.isBlank()) {
                predicates.add(cb.equal(root.get("ip"), ip.trim()));
            }
            if (username != null && !username.isBlank()) {
                predicates.add(cb.like(cb.lower(root.get("username")),
                        "%" + username.trim().toLowerCase() + "%"));
            }
            if (success != null) {
                predicates.add(cb.equal(root.get("success"), success));
            }
            if (createdFrom != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.<LocalDateTime>get("createdAt"),
                        createdFrom.atStartOfDay()));
            }
            if (createdTo != null) {
                predicates.add(cb.lessThan(root.<LocalDateTime>get("createdAt"),
                        createdTo.plusDays(1).atStartOfDay()));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}
