package com.nanxing.webhookadmissioncontroller.domin.webhook;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Author: Nanxing
 * Date: 2024/3/14 20:06
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AR_Response {
    private String uid;
    private boolean allowed;
}
