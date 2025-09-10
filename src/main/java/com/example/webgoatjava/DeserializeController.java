package com.example.webgoatjava;

import com.thoughtworks.xstream.XStream;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.oxm.xstream.XStreamMarshaller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Intentionally vulnerable XML deserialization endpoints.
 * Mirrors the style of code that uses XStream/JAXB without secure processing.
 */
@RestController
public class DeserializeController {

    @Autowired(required = false)
    private XStreamMarshaller xstreamMarshaller; // created lazily by Spring if configured

    @Autowired(required = false)
    private Jaxb2Marshaller jaxb2Marshaller;

    // 1) Insecure XStream XML deserialization (no type whitelisting)
    @PostMapping(path = "/xml/xstream", consumes = MediaType.APPLICATION_XML_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> xstream(@RequestBody String xml) {
        try {
            XStream xstream = (xstreamMarshaller != null) ? xstreamMarshaller.getXStream() : new XStream();
            // default security (since newer XStream locks down types) is NOT configured here,
            // intentionally leaving it open for training purposes.
            InputStream in = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
            Object obj = xstream.fromXML(in); // vulnerable deserialization
            return ResponseEntity.ok("XStream deserialized: " + String.valueOf(obj));
        } catch (Exception e) {
            return ResponseEntity.ok("XStream error: " + e.getMessage());
        }
    }

    // 2) Insecure JAXB unmarshal via Spring's Jaxb2Marshaller (no secure processing)
    @PostMapping(path = "/xml/jaxb", consumes = MediaType.APPLICATION_XML_VALUE, produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> jaxb(@RequestBody String xml) {
        try {
            if (jaxb2Marshaller == null) {
                jaxb2Marshaller = new Jaxb2Marshaller(); // no secureProcessing, no schema, etc.
                // Intentionally not setting classesToBeBound for strict typing; will attempt to unmarshal loosely.
            }
            InputStream in = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
            Object obj = jaxb2Marshaller.unmarshal(new StreamSource(in)); // vulnerable to XXE-style attacks in insecure configs
            return ResponseEntity.ok("JAXB deserialized: " + String.valueOf(obj));
        } catch (Exception e) {
            return ResponseEntity.ok("JAXB error: " + e.getMessage());
        }
    }
}
