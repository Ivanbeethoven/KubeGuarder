package com.nanxing.kubeguard.utils;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Objects;

/**
 * Author: Nanxing
 * Date: 2024/4/15 23:10
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PlainRule {
    private String account;
    private String apiGroup;
    private String resource;
    private String namespace;
    private String name;
    private String verb;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PlainRule plainRule = (PlainRule) o;
        return Objects.equals(account, plainRule.account) && Objects.equals(apiGroup, plainRule.apiGroup) && Objects.equals(resource, plainRule.resource) && Objects.equals(namespace, plainRule.namespace) && Objects.equals(name, plainRule.name) && Objects.equals(verb, plainRule.verb);
    }

    @Override
    public int hashCode() {
        return Objects.hash(account, apiGroup, resource, namespace, name, verb);
    }
}
