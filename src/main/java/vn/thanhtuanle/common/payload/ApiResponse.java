package vn.thanhtuanle.common.payload;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResponse<T> {
    private int status;
    private String message;
    private T data;
    private Map<String, String> errors;
    private String timestamp;

    private PageResponse<?> pagination;

    private static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

    public static <T> ApiResponse<T> success(T data) {
        return ApiResponse.<T>builder()
                .status(HttpStatus.OK.value())
                .message("Success")
                .data(data)
                .timestamp(LocalDateTime.now().format(TIMESTAMP_FORMATTER))
                .build();
    }

    public static <T> ApiResponse<T> success() {
        return ApiResponse.<T>builder()
                .status(HttpStatus.OK.value())
                .message("Success")
                .timestamp(LocalDateTime.now().format(TIMESTAMP_FORMATTER))
                .build();
    }

    public static <T> ApiResponse<List<T>> success(PageResponse<T> pageResponse) {
        List<T> data = pageResponse.getData();
        pageResponse.setData(null);
        return ApiResponse.<List<T>>builder()
                .status(HttpStatus.OK.value())
                .message("Success")
                .data(data)
                .pagination(pageResponse)
                .timestamp(LocalDateTime.now().format(TIMESTAMP_FORMATTER))
                .build();
    }

    public static <T> ApiResponse<T> success(T data, String message) {
        return ApiResponse.<T>builder()
                .status(HttpStatus.OK.value())
                .message(message)
                .data(data)
                .timestamp(LocalDateTime.now().format(TIMESTAMP_FORMATTER))
                .build();
    }

    public static <T> ApiResponse<T> created(T data) {
        return ApiResponse.<T>builder()
                .status(HttpStatus.CREATED.value())
                .message("Created")
                .data(data)
                .timestamp(LocalDateTime.now().format(TIMESTAMP_FORMATTER))
                .build();
    }

    public static <T> ApiResponse<T> error(int status, String message) {
        return ApiResponse.<T>builder()
                .status(status)
                .message(message)
                .data(null)
                .errors(null)
                .timestamp(LocalDateTime.now().format(TIMESTAMP_FORMATTER))
                .build();
    }

    public static <T> ApiResponse<T> error(int status, String message, Map<String, String> errors) {
        return ApiResponse.<T>builder()
                .status(status)
                .message(message)
                .data(null)
                .errors(errors)
                .timestamp(LocalDateTime.now().format(TIMESTAMP_FORMATTER))
                .build();
    }
}
