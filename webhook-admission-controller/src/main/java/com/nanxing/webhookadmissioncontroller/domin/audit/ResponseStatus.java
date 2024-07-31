package com.nanxing.webhookadmissioncontroller.domin.audit;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Author: Nanxing
 * Date: 2024/3/5 10:39
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResponseStatus {
    private String status;
    private String message;
    private String code;
}
