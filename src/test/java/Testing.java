import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import sg.edu.ntu.sce.sands.crypto.dcpabe.*;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PersonalKey;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;


@RunWith(JUnit4.class)
public class Testing {
    @Test
    public void testDCPABE2() {
        GlobalParameters gp = DCPABE.globalSetup(160);
        PublicKeys publicKeys = new PublicKeys();
        Pairing pairing = PairingFactory.getPairing(gp.getPairingParameters());
        Element n = pairing.getZr().newRandomElement().getImmutable();
        AuthorityKeys authority1 = DCPABE.authoritySetup("a1", gp, n,"a", "d");
        publicKeys.subscribeAuthority(authority1.getPublicKeys());

        AuthorityKeys authority2 = DCPABE.authoritySetup("a2", gp, n, "b", "c");

        publicKeys.subscribeAuthority(authority2.getPublicKeys());

        PersonalKeys pkeys = new PersonalKeys("user");
        pkeys.addKey(DCPABE.keyGen("user", "a", authority1.getSecretKeys().get("a"), gp));
        pkeys.addKey(DCPABE.keyGen("user", "d", authority1.getSecretKeys().get("d"), gp));

        AccessStructure as = AccessStructure.buildFromPolicy("and a or d and b c");

        Message message = DCPABE.generateRandomMessage(gp);
        Ciphertext ct = DCPABE.encrypt(message, as, gp, publicKeys);

        Message dmessage = DCPABE.decrypt(ct, pkeys, gp);
        System.out.println(Arrays.toString(message.getM()));
        System.out.println(Arrays.toString(dmessage.getM()));
        assertArrayEquals(message.getM(), dmessage.getM());
    }


    @Test
    public void testDCPABE1() {
        GlobalParameters gp = DCPABE.globalSetup(160);
        Pairing pairing = PairingFactory.getPairing(gp.getPairingParameters());
        Element n = pairing.getZr().newRandomElement().getImmutable();
        PublicKeys publicKeys = new PublicKeys();
        AuthorityKeys authority0 = DCPABE.authoritySetup("a1", gp, n, "a", "b", "c", "d");
        publicKeys.subscribeAuthority(authority0.getPublicKeys());

        AccessStructure as = AccessStructure.buildFromPolicy("and a or d and b c");

        PersonalKeys pkeys = new PersonalKeys("user");
        PersonalKey k_user_a = DCPABE.keyGen("user", "a", authority0.getSecretKeys().get("a"), gp);
//        PersonalKey k_user_d = DCPABE.keyGen("user", "d", authority0.getSecretKeys().get("d"), gp);
        PersonalKey k_user_b = DCPABE.keyGen("user", "b", authority0.getSecretKeys().get("b"), gp);
        PersonalKey k_user_c = DCPABE.keyGen("user", "c", authority0.getSecretKeys().get("c"), gp);
        pkeys.addKey(k_user_a);
//        pkeys.addKey(k_user_d);
        pkeys.addKey(k_user_b);
        pkeys.addKey(k_user_c);
        Message message = DCPABE.generateRandomMessage(gp);
        Ciphertext ct = DCPABE.encrypt(message, as, gp, publicKeys);

        Message dMessage = DCPABE.decrypt(ct, pkeys, gp);

        assertArrayEquals(message.getM(), dMessage.getM());
    }

    @Test
    public void testBilinearity() {
        SecureRandom random = new SecureRandom("12345".getBytes());
        Pairing pairing = PairingFactory.getPairing(new TypeACurveGenerator(random, 181, 603, true).generate());

        Element g1 = pairing.getG1().newRandomElement().getImmutable();
        Element g2 = pairing.getG2().newRandomElement().getImmutable();

        Element a = pairing.getZr().newRandomElement().getImmutable();
        Element b = pairing.getZr().newRandomElement().getImmutable();

        Element ga = g1.powZn(a);
        Element gb = g2.powZn(b);

        Element gagb = pairing.pairing(ga, gb);

        Element ggab = pairing.pairing(g1, g2).powZn(a.mulZn(b));

        assertTrue(gagb.isEqual(ggab));
    }
}
