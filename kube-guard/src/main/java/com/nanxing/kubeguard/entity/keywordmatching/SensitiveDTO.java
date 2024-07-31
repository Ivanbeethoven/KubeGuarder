package com.nanxing.kubeguard.entity.keywordmatching;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Author: Nanxing
 * Date: 2024/4/12 13:52
 */
@AllArgsConstructor
@NoArgsConstructor
@Data
public class SensitiveDTO {
    private String packetId;
    private String srcIp;
    private String srcAccount;
    private String dstIp;
    private String dstAccount;
    private String protocol;
    private String nodeIp;
    private String nodeName;
    private LeakageDetail request;
    private LeakageDetail response;
    private JSONObject packet;

    public SensitiveDTO(SensitivityResourceLeakageDetectionReport report){
        String id = report.getPacket().getString("id");
        if(id.contains("/")){
            id = id.substring(id.indexOf("/") + 1, id.length());
        }
        this.setPacketId(id);

        this.srcIp = report.getSrcIp();
        this.srcAccount = report.getSrcAccount();
        this.dstIp = report.getDstIp();
        this.dstAccount = report.getDstAccount();
        this.protocol = report.getPacket().getJSONObject("protocol").getString("name").toUpperCase();
        JSONObject node = report.getPacket().getJSONObject("node");
        this.nodeIp = node.getString("ip");
        this.nodeName = node.getString("name");
        this.request = report.getRequest();
        this.response = report.getResponse();
        this.packet = report.getPacket();

    }
}
