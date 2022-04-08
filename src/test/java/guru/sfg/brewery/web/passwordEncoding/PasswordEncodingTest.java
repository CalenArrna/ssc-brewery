package guru.sfg.brewery.web.passwordEncoding;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.util.DigestUtils;


public class PasswordEncodingTest {

    static final String PASSWORD = "password";

    @Test
    void passwordHashingWithBCrypt() {
        PasswordEncoder bCrypt = new BCryptPasswordEncoder(12);
        System.out.println(bCrypt.encode("guru"));
//        System.out.println(bCrypt.encode(PASSWORD));
    }

    @Test
    void passwordHashingWithSHA() {
        PasswordEncoder sha256 = new StandardPasswordEncoder();
        System.out.println(sha256.encode(PASSWORD));
//        System.out.println(sha256.encode(PASSWORD));
    }

    @Test
    void passwordHashingWithCustomBcrypt15() {
        PasswordEncoder bCrypt12 = new BCryptPasswordEncoder(12);
        System.out.println(bCrypt12.encode("tiger"));
    }

    @Test
    void passwordHasingWithLDAP() {
        PasswordEncoder ldap = new LdapShaPasswordEncoder();
        System.out.println(ldap.encode("tiger"));
//        System.out.println(ldap.encode(PASSWORD));
    }

    @Test
    void paswordHashingWithNOOP() {
        PasswordEncoder noOp = NoOpPasswordEncoder.getInstance();
        System.out.println(noOp.encode(PASSWORD));
    }

    @Test
    void passwordHashingWithMD5() {
        System.out.println(DigestUtils.md5DigestAsHex(PASSWORD.getBytes()));
        System.out.println(DigestUtils.md5DigestAsHex(PASSWORD.getBytes()));

        String saltedPwd = PASSWORD + "MyPasswordSaltValueToAdd";

        System.out.println(DigestUtils.md5DigestAsHex(saltedPwd.getBytes()));
    }
}
