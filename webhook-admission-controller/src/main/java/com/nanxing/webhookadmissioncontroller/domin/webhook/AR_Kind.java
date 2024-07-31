package com.nanxing.webhookadmissioncontroller.domin.webhook;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Author: Nanxing
 * Date: 2024/3/14 20:09
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AR_Kind {
    private String group;
    private String version;
    private String kind;
}
