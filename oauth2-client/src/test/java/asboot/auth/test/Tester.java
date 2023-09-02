package asboot.auth.test;

import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Tester {
	
	private static final Logger LOG = LoggerFactory.getLogger(Tester.class);

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		new Tester().test1();
	}
	
	public void test1() {
		
		String clientId = "messaging-client";
		LOG.info("clientId:{}", clientId);
		String clientSecret = "secret";
		LOG.info("clientSecret:{}", clientSecret);
		
		String src = String.format("%s:%s", clientId, clientSecret);
		LOG.info("src:{}", src);
		
		String authorization = Base64.getEncoder().encodeToString(src.getBytes());
		System.out.println(authorization);
	}

}
