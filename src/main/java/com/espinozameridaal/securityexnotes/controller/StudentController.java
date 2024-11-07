package com.espinozameridaal.securityexnotes.controller;

import com.espinozameridaal.securityexnotes.model.JobApplication;
import jakarta.servlet.http.HttpServletRequest;
import com.espinozameridaal.securityexnotes.model.Student;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;



// with the security configuration you provided,
// all endpoints, including the ones in your StudentController,
// will require authentication. Since you've set up security with in security config:
//.authorizeHttpRequests(request -> request.anyRequest().authenticated())


//Authentication Required:
//All HTTP requests (including GET, POST, etc.) to the /students and /csrf-token
// endpoints will trigger Spring Security to check if the request has proper authentication
// (like a valid username and password).
//Without valid credentials, the server will return a 401 Unauthorized response.
@RestController
public class StudentController {

    List<JobApplication> jobApplications = new ArrayList<>(
            List.of(
                    new JobApplication("Google", "Software Engineer"),
                    new JobApplication("Microsoft", "Backend Developer"),
                    new JobApplication("Amazon", "Cloud Engineer"),
                    new JobApplication("Apple", "iOS Developer"),
                    new JobApplication("Facebook", "Data Scientist"),
                    new JobApplication("Netflix", "DevOps Engineer"),
                    new JobApplication("Tesla", "AI Researcher"),
                    new JobApplication("Airbnb", "Full Stack Developer"),
                    new JobApplication("Uber", "Mobile Developer"),
                    new JobApplication("Salesforce", "Solutions Architect")
            )
    );


    @GetMapping("/applications")
    public List<JobApplication> getStudents() {
        return jobApplications;
    }

    @GetMapping("/csrf-token")
    public CsrfToken getCsrfToken(HttpServletRequest request) {
        return (CsrfToken) request.getAttribute("_csrf");

    }


//    @PostMapping("/applications")
//    public Student addStudent(@RequestBody Student student) {
//        students.add(student);
//        return student;
//    }

}
