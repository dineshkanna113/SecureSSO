package com.example.finalsso.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
@Order(0)
public class DbMigrationRunner implements CommandLineRunner {

	private final JdbcTemplate jdbcTemplate;

	public DbMigrationRunner(JdbcTemplate jdbcTemplate) {
		this.jdbcTemplate = jdbcTemplate;
	}

	@Override
	public void run(String... args) {
		// Ensure new columns exist on pre-existing users table
		jdbcTemplate.execute("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS first_name varchar(255)");
		jdbcTemplate.execute("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS last_name varchar(255)");
		jdbcTemplate.execute("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS role varchar(255) DEFAULT 'ROLE_USER' NOT NULL");
		jdbcTemplate.execute("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS enabled boolean DEFAULT TRUE NOT NULL");
	}
}


