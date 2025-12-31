package com.leeyujin.api.oauthservice.user.oauth;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * OAuth Provider 선택을 위한 Factory
 * Spring의 의존성 주입을 통해 모든 OAuthClient 구현체를 자동으로 수집합니다.
 */
@Component
public class OAuthClientFactory {

    private final Map<String, OAuthClient> oauthClients;

    public OAuthClientFactory(List<OAuthClient> oauthClients) {
        this.oauthClients = oauthClients.stream()
                .collect(Collectors.toMap(
                        OAuthClient::getProviderName,
                        Function.identity()
                ));
    }

    /**
     * Provider 이름으로 OAuthClient 조회
     * @param providerName provider 이름 (google, kakao, naver)
     * @return OAuthClient 구현체
     * @throws IllegalArgumentException 지원하지 않는 provider인 경우
     */
    public OAuthClient getClient(String providerName) {
        OAuthClient client = oauthClients.get(providerName.toLowerCase());
        if (client == null) {
            throw new IllegalArgumentException("지원하지 않는 OAuth Provider: " + providerName);
        }
        return client;
    }
}

