package com.example;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.util.Map;

public class XxeSafe {
    public Map<String, Object> parseJson(InputStream input) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(input, Map.class);
    }
}
