package vn.thanhtuanle.common.enums;

import lombok.Getter;

@Getter
public enum CommonStatus {
    ACTIVE(1),
    INACTIVE(0);

    private final int value;

    CommonStatus(int value) {
        this.value = value;
    }

    public static CommonStatus fromValue(int value) {
        for (CommonStatus status : CommonStatus.values()) {
            if (status.getValue() == value) {
                return status;
            }
        }
        throw new IllegalArgumentException("Invalid CommonStatus value: " + value);
    }

}
