package vn.thanhtuanle.common.payload;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.domain.Page;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PageResponse<T> {
    private List<T> data;
    private int page;
    private int size;
    private long totalElements;
    private int totalPages;
    private boolean hasPrev;
    private boolean hasNext;
    private int prevPage;
    private int nextPage;

    public static <T> PageResponse<T> of(Page<T> page) {
        return PageResponse.<T>builder()
                .data(page.getContent())
                .page(page.getNumber())
                .size(page.getSize())
                .totalElements(page.getTotalElements())
                .totalPages(page.getTotalPages())
                .hasPrev(page.hasPrevious())
                .hasNext(page.hasNext())
                .prevPage(page.getNumber() - 1 > 0 ? page.getNumber() - 1 : 0)
                .nextPage(page.getNumber() + 1 < page.getTotalPages() ? page.getNumber() + 1 : page.getTotalPages())
                .build();
    }
}
