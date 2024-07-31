package com.nanxing.webhookadmissioncontroller.domin.webhook;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Author: Nanxing
 * Date: 2024/3/14 20:01
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AdmissionReview {
    private String apiVersion;
    private String kind;
    private AR_Request request;
    private AR_Response response;
}
