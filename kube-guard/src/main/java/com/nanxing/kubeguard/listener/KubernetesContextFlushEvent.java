package com.nanxing.kubeguard.listener;

import org.springframework.context.ApplicationEvent;

/**
 * Author: Nanxing
 * Date: 2024/3/18 21:18
 */
public class KubernetesContextFlushEvent extends ApplicationEvent {
    public KubernetesContextFlushEvent(Object source) {
        super(source);
    }
}
