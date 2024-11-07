package com.espinozameridaal.securityexnotes.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString

public class JobApplication {
    private String companyName; // name of the company the application is for
    private String positionTitle;

    public JobApplication(String companyName, String positionTitle) {
        this.companyName = companyName;
        this.positionTitle = positionTitle;
    }

}
