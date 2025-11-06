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
		// Create tenant_master table if it doesn't exist
		jdbcTemplate.execute("""
			CREATE TABLE IF NOT EXISTS tenant_master (
				tenant_id BIGSERIAL PRIMARY KEY,
				tenant_name VARCHAR(255) UNIQUE NOT NULL,
				created_by VARCHAR(255) NOT NULL,
				active BOOLEAN NOT NULL DEFAULT TRUE,
				created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
			)
		""");
		
		// Ensure new columns exist on pre-existing users table
		jdbcTemplate.execute("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS first_name varchar(255)");
		jdbcTemplate.execute("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS last_name varchar(255)");
		jdbcTemplate.execute("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS role varchar(255) DEFAULT 'END_USER' NOT NULL");
		jdbcTemplate.execute("ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS enabled boolean DEFAULT TRUE NOT NULL");
		
		// Add tenant_id column for multi-tenant support (only if not exists)
		try {
			jdbcTemplate.execute("ALTER TABLE users ADD COLUMN tenant_id bigint");
		} catch (Exception e) {
			// Column already exists, ignore
		}
		
		// Add foreign key constraint (drop if exists first, then add)
		try {
			jdbcTemplate.execute("ALTER TABLE users DROP CONSTRAINT IF EXISTS fk_user_tenant");
		} catch (Exception e) {
			// Ignore if constraint doesn't exist
		}
		try {
			jdbcTemplate.execute("ALTER TABLE users ADD CONSTRAINT fk_user_tenant FOREIGN KEY (tenant_id) REFERENCES tenant_master(tenant_id) ON DELETE SET NULL");
		} catch (Exception e) {
			// Constraint might already exist, ignore
		}
		
		// Migrate existing role values to new enum format
		// ROLE_ADMIN -> SUPER_ADMIN, ROLE_USER -> END_USER
		jdbcTemplate.update("UPDATE users SET role = 'SUPER_ADMIN' WHERE role = 'ROLE_ADMIN' OR role = 'ADMIN'");
		jdbcTemplate.update("UPDATE users SET role = 'END_USER' WHERE role = 'ROLE_USER' OR role = 'USER' OR role IS NULL OR role = ''");

    }
}


