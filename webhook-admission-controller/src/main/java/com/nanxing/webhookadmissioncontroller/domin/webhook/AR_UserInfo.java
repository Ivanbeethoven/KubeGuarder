package com.nanxing.webhookadmissioncontroller.domin.webhook;

import com.alibaba.fastjson.JSONObject;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Author: Nanxing
 * Date: 2024/3/14 20:17
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AR_UserInfo {
    private String username;
    private String uid;
    private List<String> groups;
    private JSONObject extra;
}
