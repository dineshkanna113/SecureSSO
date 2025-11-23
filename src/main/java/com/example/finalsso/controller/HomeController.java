package com.example.finalsso.controller;

import com.example.finalsso.entity.BugReport;
import com.example.finalsso.repository.BugReportRepository;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class HomeController {

	private final BugReportRepository bugReportRepository;

	public HomeController(BugReportRepository bugReportRepository) {
		this.bugReportRepository = bugReportRepository;
	}

	@GetMapping("/hello")
	public String helloPage(@AuthenticationPrincipal Object principal, Model model) {
		if (principal instanceof OidcUser) {
			OidcUser oidcUser = (OidcUser) principal;
			model.addAttribute("name", oidcUser.getFullName());
			model.addAttribute("email", oidcUser.getEmail());
		} else if (principal instanceof Saml2AuthenticatedPrincipal samlUser) {
			model.addAttribute("name", samlUser.getName());
			model.addAttribute("email", samlUser.getFirstAttribute("email"));
			model.addAttribute("method", "SAML 2.0 (Okta)");
		} else {
			model.addAttribute("name", "Local User");
			model.addAttribute("email", "N/A");
		}
		return "hello";
	}

	@GetMapping("/bug-report")
	public String showBugReportForm(Model model) {
		model.addAttribute("title", "Report a Bug");
		return "bug_report_form";
	}

	@PostMapping("/bug-report")
	public String submitBugReport(@RequestParam String reporterEmail,
	                              @RequestParam String issueSummary,
	                              @RequestParam String issueDescription,
	                              RedirectAttributes ra) {
		BugReport report = new BugReport();
		report.setReporterEmail(reporterEmail.trim());
		report.setSummary(issueSummary.trim());
		report.setDescription(issueDescription.trim());
		bugReportRepository.save(report);

		ra.addFlashAttribute("success", "Thank you! Your bug report has been submitted and will be reviewed by our administrators.");
		return "redirect:/login";
	}
}
