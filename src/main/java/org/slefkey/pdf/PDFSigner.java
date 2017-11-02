package org.slefkey.pdf;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.*;
import org.apache.commons.cli.*;
import org.apache.maven.shared.utils.cli.WriterStreamConsumer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


import java.io.*;
import java.security.*;
import java.security.cert.Certificate;

public class PDFSigner {

    public static void main(String[] args) {
        try {
            Writer console = new BufferedWriter(new OutputStreamWriter(System.out));

            WriterStreamConsumer systemOut = new WriterStreamConsumer(console);
            WriterStreamConsumer systemErr = new WriterStreamConsumer(console);

            Options options = new Options();

            options.addOption("input", true, "pdf file to sign");
            options.addOption("output", true, "signed pdf file to save");
            options.addOption("cert", true, "certificate file");
            options.addOption("password", true, "certificate password");

            CommandLineParser parser = new DefaultParser();
            CommandLine cmd = parser.parse(options, args);

            if(!cmd.hasOption("input") || !cmd.hasOption("output") || !cmd.hasOption("cert") || !cmd.hasOption("password")){
                System.out.println("Missing Required Arguments");
                return;
            }

            String inputSrc = cmd.getOptionValue("input");
            String outputSrc = cmd.getOptionValue("output");
            String certSrc = cmd.getOptionValue("cert");
            String certPass = cmd.getOptionValue("password"); //  "asdASD123!"

            String signAlgorithm = "sha1";
            String signReason = "Test Reason";
            String signLocation = "Test Sign Location";


            char[] pass = certPass.toCharArray();

            BouncyCastleProvider provider = new BouncyCastleProvider();
            Security.addProvider(provider);

            KeyStore ks = KeyStore.getInstance("pkcs12");

            ks.load(new FileInputStream(certSrc), pass);

            String alias = ks.aliases().nextElement();
            PrivateKey pk = (PrivateKey) ks.getKey(alias, pass);

            Certificate[] chain = ks.getCertificateChain(alias);

            String done = new PDFSigner().sign(
                    inputSrc,
                    outputSrc,
                    chain,
                    pk,
                    signAlgorithm,
                    provider.getName(),
                    PdfSigner.CryptoStandard.CMS,
                    signReason,
                    signLocation
            );

            systemOut.consumeLine(done);
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
    }


    private String sign(String src, String dest, Certificate[] chain, PrivateKey pk, String digestAlgorithm, String provider, com.itextpdf.signatures.PdfSigner.CryptoStandard subfilter, String reason, String location) {
        try {
            PdfReader reader = new PdfReader(src);

            PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), false);

            // Creating the appearance
            PdfSignatureAppearance appearance = signer
                    .getSignatureAppearance()
                    .setReason(reason)
                    .setLocation(location)
                    .setReuseAppearance(false);

            Rectangle rect = new Rectangle(0, 0, 200, 100);

            appearance.setPageRect(rect).setPageNumber(1);
            signer.setFieldName("sig");

            // Creating the signature
            IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);

            IExternalDigest digest = new BouncyCastleDigest();
            signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);

            reader.close();

            return "done";
        } catch (Exception e){
            return e.getMessage();
        }
    }
}
