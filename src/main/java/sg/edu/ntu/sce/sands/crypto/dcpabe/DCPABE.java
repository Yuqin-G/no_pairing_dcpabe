package sg.edu.ntu.sce.sands.crypto.dcpabe;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure;
import sg.edu.ntu.sce.sands.crypto.dcpabe.ac.AccessStructure.MatrixElement;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PersonalKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.PublicKey;
import sg.edu.ntu.sce.sands.crypto.dcpabe.key.SecretKey;

import java.util.ArrayList;
import java.util.List;

public class DCPABE {
    public static GlobalParameters globalSetup(int lambda) {
        GlobalParameters params = new GlobalParameters();

//        params.setPairingParameters(new TypeA1CurveGenerator(3, lambda).generate());
        params.setPairingParameters(new TypeACurveGenerator(160, 512).generate());
        Pairing pairing = PairingFactory.getPairing(params.getPairingParameters());

        params.setG1(pairing.getGT().newRandomElement().getImmutable());

        return params;
    }

    public static AuthorityKeys authoritySetup(String authorityID, GlobalParameters GP, Element n, String... attributes) {
        AuthorityKeys authorityKeys = new AuthorityKeys(authorityID);

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        for (String attribute : attributes) {
            Element ki = pairing.getZr().newRandomElement().getImmutable();
//            Element yi = pairing.getZr().newRandomElement().getImmutable();

            authorityKeys.getPublicKeys().put(attribute, new PublicKey(
                    GP.getG1().mulZn(ki).toBytes(),
                    GP.getG1().mulZn(n).toBytes()));

            authorityKeys.getSecretKeys().put(attribute, new SecretKey(ki.toBytes(), n.toBytes()));
        }
        return authorityKeys;
    }

    public static Ciphertext encrypt(Message message, AccessStructure arho, GlobalParameters GP, PublicKeys pks) {
        Ciphertext ct = new Ciphertext();

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());
        Element M = pairing.getGT().newZeroElement();
        M.setFromBytes(message.getM());
        M = M.getImmutable(); // message

        Element s = pairing.getZr().newRandomElement().getImmutable();

        List<Element> v = new ArrayList<Element>(arho.getL());

        v.add(s);

        for (int i = 1; i < arho.getL(); i++) {
            v.add(pairing.getZr().newRandomElement().getImmutable());
        }

        List<Element> w = new ArrayList<>();
        w.add(pairing.getZr().newZeroElement().getImmutable());
        for (int i = 1; i < arho.getL(); i++) {
            w.add(pairing.getZr().newRandomElement().getImmutable());
        }

        ct.setAccessStructure(arho);

        ct.setC0(M.add(GP.getG1().mulZn(s)).toBytes()); // C_0 = M + sG

        for (int x = 0; x < arho.getN(); x++) {
            Element lambdax = dotProduct(arho.getRow(x), v, pairing.getZr().newZeroElement(), pairing);
            Element wx = dotProduct(arho.getRow(x), w, pairing.getZr().newZeroElement(), pairing);

            //c1
            Element c1x1 = GP.getG1().mulZn(lambdax);
            Element c1x2 = pairing.getGT().newElement();
            c1x2.setFromBytes(pks.getPK(arho.rho(x)).getEg1g1ai()); //PK_rho(x)
            c1x2.mulZn(wx);

            ct.setC1(c1x1.add(c1x2).toBytes());

            ct.setC2(GP.getG1().mulZn(wx).toBytes());
        }

        return ct;
    }

    public static Message decrypt(Ciphertext CT, PersonalKeys pks, GlobalParameters GP) {
        List<Integer> toUse = CT.getAccessStructure().getIndexesList(pks.getAttributes());

        if (null == toUse || toUse.isEmpty()) throw new IllegalArgumentException("Not satisfying");

        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());

        Element t = pairing.getGT().newZeroElement();

        for (Integer x : toUse) {
            Element key = pairing.getZr().newElement(); // SK_rou(x),GID
            key.setFromBytes(pks.getKey(CT.getAccessStructure().rho(x)).getKey());
            Element c2x = pairing.getGT().newElement();
            c2x.setFromBytes(CT.getC2(x));
            Element p1 = c2x.mulZn(key);

            Element c1x = pairing.getGT().newElement();
            c1x.setFromBytes(CT.getC1(x));
            Element p2 = c1x.sub(p1);
            t.add(p2);
        }

        Element c0 = pairing.getGT().newElement();
        c0.setFromBytes(CT.getC0());
        c0.sub(t);
        return new Message(c0.toBytes());
    }

    public static PersonalKey keyGen(String userID, String attribute, SecretKey sk, GlobalParameters GP) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());

        Element HGID = pairing.getZr().newElement();
        HGID.setFromHash(userID.getBytes(), 0, userID.getBytes().length);
        Element ki = pairing.getZr().newElement();
        ki.setFromBytes(sk.getAi());
        Element n = pairing.getZr().newElement();
        n.setFromBytes(sk.getYi());
        return new PersonalKey(attribute, ki.add(HGID.mulZn(n)).toBytes());
    }

    private static Element dotProduct(List<MatrixElement> v1, List<Element> v2, Element element, Pairing pairing) {
        if (v1.size() != v2.size()) throw new IllegalArgumentException("different length");
        if (element.isImmutable()) throw new IllegalArgumentException("immutable");

        if (!element.isZero())
            element.setToZero();

        for (int i = 0; i < v1.size(); i++) {
            Element e = pairing.getZr().newElement();
            switch (v1.get(i)) {
                case MINUS_ONE:
                    e.setToOne().negate();
                    break;
                case ONE:
                    e.setToOne();
                    break;
                case ZERO:
                    e.setToZero();
                    break;
            }
            element.add(e.mul(v2.get(i).getImmutable()));
        }

        return element.getImmutable();
    }

    public static Message generateRandomMessage(GlobalParameters GP) {
        Pairing pairing = PairingFactory.getPairing(GP.getPairingParameters());

        Element M = pairing.getGT().newRandomElement().getImmutable();

        return new Message(M.toBytes());
    }


    public static long basicTest1(int num)  {
        GlobalParameters gp = DCPABE.globalSetup(160);
        PublicKeys publicKeys = new PublicKeys();
        String policy = "";
        PersonalKeys pkeys = new PersonalKeys("user");
        Pairing pairing = PairingFactory.getPairing(gp.getPairingParameters());
        Element n = pairing.getZr().newRandomElement().getImmutable();
        for (int i = 1; i <= num; i ++ ) {
            AuthorityKeys authority = DCPABE.authoritySetup("a", gp, n, "s"+i);
            publicKeys.subscribeAuthority(authority.getPublicKeys());
            pkeys.addKey(DCPABE.keyGen("user", "s"+i, authority.getSecretKeys().get("s"+i), gp));
            if (i == num) policy = policy + ("s"+ i);
            else policy = policy +  "and " + ("s" + i) + " ";
            }
//        System.out.println(policy);
        AccessStructure as = AccessStructure.buildFromPolicy(policy);
        Message message = DCPABE.generateRandomMessage(gp);
        long startTime = System.currentTimeMillis();
        Ciphertext ct = DCPABE.encrypt(message, as, gp, publicKeys);
        long time = System.currentTimeMillis()-startTime;
        Message dmessage = DCPABE.decrypt(ct, pkeys, gp);
        return time;
    }
    public static long basicTest2(int num)  {
        GlobalParameters gp = DCPABE.globalSetup(160);
        PublicKeys publicKeys = new PublicKeys();
        String policy = "";
        PersonalKeys pkeys = new PersonalKeys("user");
        Pairing pairing = PairingFactory.getPairing(gp.getPairingParameters());
        Element n = pairing.getZr().newRandomElement().getImmutable();
        for (int i = 1; i <= num; i ++ ) {
            AuthorityKeys authority = DCPABE.authoritySetup("a", gp, n, "s"+i);
            publicKeys.subscribeAuthority(authority.getPublicKeys());
            pkeys.addKey(DCPABE.keyGen("user", "s"+i, authority.getSecretKeys().get("s"+i), gp));
            if (i == num) policy = policy + ("s"+ i);
            else policy = policy +  "and " + ("s" + i) + " ";
        }
//        System.out.println(policy);
        AccessStructure as = AccessStructure.buildFromPolicy(policy);
        Message message = DCPABE.generateRandomMessage(gp);

        Ciphertext ct = DCPABE.encrypt(message, as, gp, publicKeys);
        long startTime = System.currentTimeMillis();
        Message dmessage = DCPABE.decrypt(ct, pkeys, gp);
        long time = System.currentTimeMillis()-startTime;
        return time;
    }
    public static void main(String arg[]) {
        // encryption
//        int num = 5;
//        float [] encrypt = new float[10];
//        for (int i = 0; i < 10; i ++ ) {
//            long time = 0;
//            float cnt = 100;
//            for (int j = 0; j < cnt; j ++) {
//                time += basicTest1(num);
//            }
//            encrypt[i] = time / cnt;
//            num += 5;
//        }
//        for (int i = 0; i < 10; i ++)
//            System.out.println(encrypt[i]);
        // decryption
        System.out.println("************");
        int num = 5;
        float [] decrypt = new float[10];
        for (int i = 0; i < 10; i ++ ) {
            long time = 0;
            float cnt = 100;
            for (int j = 0; j < cnt; j ++) {
                time += basicTest2(num);
            }
            decrypt[i] = time / cnt;
            num += 5;
        }
        for (int i = 0; i < 10; i ++)
            System.out.println(decrypt[i]);

    }
}