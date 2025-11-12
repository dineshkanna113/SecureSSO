package com.example.finalsso.repository;

import com.example.finalsso.entity.BugReport;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface BugReportRepository extends JpaRepository<BugReport, Long> {
	List<BugReport> findAllByOrderByCreatedAtDesc();
	long countByResolvedFalse();
}


