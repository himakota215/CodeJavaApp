package net.codejava;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase.Replace;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.annotation.Rollback;
@DataJpaTest
@AutoConfigureTestDatabase(replace=Replace.NONE)
@Rollback(false)

public class UserRepositoryTests {

	@Autowired
	private UserRepository repo;
	
	@Autowired
	private TestEntityManager entityManager;
	
	@Test
	public void testCreateUser() {
		User user=new User();
		user.setEmail("24b01a12Z2@svecw.edu.in");
		user.setPassword("SVECW@2050");
		user.setFirstName("Alexander");
		user.setLastName("Kumar");
		
		User savedUser = repo.save(user);
		
		User existUser = entityManager.find(User.class,savedUser.getId());
		
		assertThat(existUser.getEmail()).isEqualTo(user.getEmail());
		
	}	
	
	@Test
	public void testFindindUserByEmail() {
		String email = " 24b01a12z2@svecw.edu.in";
		
		User user = repo.findByEmail(email);
		
		assertThat(user).isNotNull();
	}
}