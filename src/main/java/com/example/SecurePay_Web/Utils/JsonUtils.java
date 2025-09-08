package com.example.SecurePay_Web.Utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;

public class JsonUtils {

    private static final ObjectMapper mapper = new ObjectMapper();

    // Convert JSON string to Map
    public static Map<String, Object> jsonToMap(String json) throws Exception {
        return mapper.readValue(json, Map.class);
    }

    // Convert Map to JSON string
    public static String mapToJson(Map<String, Object> map) throws Exception {
        return mapper.writeValueAsString(map);
    }
}
