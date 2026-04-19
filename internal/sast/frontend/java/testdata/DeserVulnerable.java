package com.example;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

public class DeserVulnerable {
    public Object deserialize(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }
}
