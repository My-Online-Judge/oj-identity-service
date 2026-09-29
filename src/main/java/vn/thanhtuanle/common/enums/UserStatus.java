package vn.thanhtuanle.common.enums;

/**
 * Lifecycle state of a user account. Stored as the {@code Integer status} column on
 * {@code t_users}. {@code ACTIVE} maps to the same value as {@link CommonStatus#ACTIVE},
 * so pre-existing rows remain active. Only {@code ACTIVE} users may log in.
 */
public enum UserStatus {
    ACTIVE(1),
    DISABLED(0),
    DELETED(2);

    private final int value;

    UserStatus(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static UserStatus fromValue(int value) {
        for (UserStatus status : values()) {
            if (status.value == value) {
                return status;
            }
        }
        throw new IllegalArgumentException("Invalid UserStatus value: " + value);
    }
}
