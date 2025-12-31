package com.leeyujin.api.oauthservice.user.oauth.kakao.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

public class KakaoUserinfo {
    private Long id;

    @JsonProperty("kakao_account")
    private KakaoAccount kakaoAccount;

    @JsonProperty("properties")
    private Map<String, String> properties;

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public KakaoAccount getKakaoAccount() {
        return kakaoAccount;
    }

    public void setKakaoAccount(KakaoAccount kakaoAccount) {
        this.kakaoAccount = kakaoAccount;
    }

    public Map<String, String> getProperties() {
        return properties;
    }

    public void setProperties(Map<String, String> properties) {
        this.properties = properties;
    }

    // Inner class for kakao_account
    public static class KakaoAccount {
        private Boolean emailNeedsAgreement;
        private Boolean isEmailValid;
        private Boolean isEmailVerified;
        private String email;
        private Boolean hasEmail;
        private Boolean hasAgeRange;
        private String ageRange;
        private Boolean hasBirthday;
        private String birthday;
        private String birthdayType;
        private Boolean hasGender;
        private String gender;

        private Profile profile;

        // Getters and Setters
        public Boolean getEmailNeedsAgreement() {
            return emailNeedsAgreement;
        }

        public void setEmailNeedsAgreement(Boolean emailNeedsAgreement) {
            this.emailNeedsAgreement = emailNeedsAgreement;
        }

        public Boolean getIsEmailValid() {
            return isEmailValid;
        }

        public void setIsEmailValid(Boolean isEmailValid) {
            this.isEmailValid = isEmailValid;
        }

        public Boolean getIsEmailVerified() {
            return isEmailVerified;
        }

        public void setIsEmailVerified(Boolean isEmailVerified) {
            this.isEmailVerified = isEmailVerified;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public Boolean getHasEmail() {
            return hasEmail;
        }

        public void setHasEmail(Boolean hasEmail) {
            this.hasEmail = hasEmail;
        }

        public Profile getProfile() {
            return profile;
        }

        public void setProfile(Profile profile) {
            this.profile = profile;
        }

        public Boolean getHasAgeRange() {
            return hasAgeRange;
        }

        public void setHasAgeRange(Boolean hasAgeRange) {
            this.hasAgeRange = hasAgeRange;
        }

        public String getAgeRange() {
            return ageRange;
        }

        public void setAgeRange(String ageRange) {
            this.ageRange = ageRange;
        }

        public Boolean getHasBirthday() {
            return hasBirthday;
        }

        public void setHasBirthday(Boolean hasBirthday) {
            this.hasBirthday = hasBirthday;
        }

        public String getBirthday() {
            return birthday;
        }

        public void setBirthday(String birthday) {
            this.birthday = birthday;
        }

        public String getBirthdayType() {
            return birthdayType;
        }

        public void setBirthdayType(String birthdayType) {
            this.birthdayType = birthdayType;
        }

        public Boolean getHasGender() {
            return hasGender;
        }

        public void setHasGender(Boolean hasGender) {
            this.hasGender = hasGender;
        }

        public String getGender() {
            return gender;
        }

        public void setGender(String gender) {
            this.gender = gender;
        }

        // Inner class for profile
        public static class Profile {
            private String nickname;
            private String thumbnailImageUrl;
            private String profileImageUrl;
            private Boolean isDefaultImage;

            // Getters and Setters
            public String getNickname() {
                return nickname;
            }

            public void setNickname(String nickname) {
                this.nickname = nickname;
            }

            public String getThumbnailImageUrl() {
                return thumbnailImageUrl;
            }

            public void setThumbnailImageUrl(String thumbnailImageUrl) {
                this.thumbnailImageUrl = thumbnailImageUrl;
            }

            public String getProfileImageUrl() {
                return profileImageUrl;
            }

            public void setProfileImageUrl(String profileImageUrl) {
                this.profileImageUrl = profileImageUrl;
            }

            public Boolean getIsDefaultImage() {
                return isDefaultImage;
            }

            public void setIsDefaultImage(Boolean isDefaultImage) {
                this.isDefaultImage = isDefaultImage;
            }
        }
    }
}

