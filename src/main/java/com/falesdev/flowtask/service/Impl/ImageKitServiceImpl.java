package com.falesdev.flowtask.service.Impl;

import com.falesdev.flowtask.exception.ExternalServiceException;
import com.falesdev.flowtask.service.ImageKitService;
import io.imagekit.sdk.ImageKit;
import io.imagekit.sdk.config.Configuration;
import io.imagekit.sdk.models.FileCreateRequest;
import io.imagekit.sdk.models.results.Result;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class ImageKitServiceImpl implements ImageKitService {

    @Value("${imagekit.public-key}")
    private String publicKey;

    @Value("${imagekit.private-key}")
    private String privateKey;

    @Value("${imagekit.url-endpoint}")
    private String urlEndpoint;

    private ImageKit imageKit;

    @PostConstruct
    public void init() {
        imageKit = ImageKit.getInstance();
        Configuration config = new Configuration(publicKey, privateKey, urlEndpoint);
        imageKit.setConfig(config);
    }

    public String uploadImage(byte[] fileBytes, String fileName) {
        FileCreateRequest request = new FileCreateRequest(fileBytes, fileName);
        request.setFolder("/flow-user-profiles");
        request.setUseUniqueFileName(true);

        try {
            Result result = imageKit.upload(request);
            return result.getUrl();
        } catch (Exception e) {
            throw new ExternalServiceException("Error uploading image to ImageKit", e);
        }
    }
}
