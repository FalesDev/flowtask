package com.falesdev.flowtask.domain.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class MiniOnBoardingRequest {

    private String started;
    private List<String> functions;
    private String imageUrl;
}
