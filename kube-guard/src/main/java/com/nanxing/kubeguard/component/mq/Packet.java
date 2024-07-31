package com.nanxing.kubeguard.component.mq;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * Author: Nanxing
 * Date: 2024/3/20 17:51
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Packet implements Serializable {
    private String id;
    private String context;
}
