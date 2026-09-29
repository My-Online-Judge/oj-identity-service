package vn.thanhtuanle.common.constant;

/**
 * Canonical permission strings (resource:action). These are the authority values emitted by
 * {@code SecurityUserDetails} and referenced by seed data / tests. {@code @PreAuthorize}
 * annotations use the literal strings (SpEL cannot cleanly reference these constants), so keep
 * the two in sync.
 */
public final class Permissions {

    private Permissions() {}

    public static final String PROBLEM_CREATE = "problem:create";
    public static final String PROBLEM_UPDATE = "problem:update";
    public static final String PROBLEM_DELETE = "problem:delete";
    public static final String JUDGESERVER_READ = "judgeserver:read";
    public static final String SUBMISSION_READ_ANY = "submission:read_any";
}
