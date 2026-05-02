package com.example;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class DeserSafe {
    public String readFile(String path) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(path));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line).append("\n");
        }
        reader.close();
        return sb.toString();
    }
}
