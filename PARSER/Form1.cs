using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Web.Script.Serialization;
using System.Runtime.Serialization.Json;
using System.Runtime.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System.Security.Cryptography;
using System.IO;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using System.Collections;
using Org.BouncyCastle.Asn1;

namespace PARSER
{
    public partial class Form1 : Form
    {
        public string file = @"C:\Users\NakkiCalvin\openssl\serv\cert\server.crt";

        public Form1()
        {
            InitializeComponent();
        }

        public byte[] ReadFile(String filen)
        {
            var f = new FileStream(filen, FileMode.Open, FileAccess.Read);
            int size = (int)f.Length;
            byte[] data = new byte[size];
            size = f.Read(data, 0, size);
            f.Close();
            return data;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            try
            {
                file = textBox1.Text;

                X509Certificate2 cert = new X509Certificate2();
                byte[] rawData = ReadFile(file);

                cert.Import(rawData);
                textBox2.Text = cert.Subject;
                textBox3.Text = cert.Issuer;
                textBox4.Text = cert.Version.ToString();
                textBox5.Text = cert.NotBefore.ToString();
                textBox6.Text = cert.NotAfter.ToString();
                textBox7.Text = cert.Thumbprint;
                textBox8.Text = cert.SerialNumber;
                textBox10.Text = cert.PublicKey.Oid.FriendlyName;
                textBox11.Text = cert.PublicKey.EncodedKeyValue.Format(true);
                textBox12.Text = cert.RawData.Length.ToString();
                textBox9.Text = cert.ToString(true);

                X509Store store = new X509Store();
                store.Open(OpenFlags.MaxAllowed);
                store.Add(cert);
                store.Close();
            }

            catch (Exception ex)
            {
                ex.ToString();
            }

            //try
            //{
            //    //var path = "C:/Users/NakkiCalvin/openssl/serv/cert/server.crt";
            //    var path = textBox1.Text;

            //    X509Certificate2 cert = new X509Certificate2(path);

            //    certMy my = new certMy();

            //    my.hash = cert.GetCertHashString();
            //    my.EffectiveDateString = cert.GetEffectiveDateString();
            //    my.ExpirationDateString = cert.GetExpirationDateString();
            //    my.GetFormat = cert.GetFormat();
            //    my.IssuerName = cert.GetIssuerName();
            //    my.KeyAlgorithm = cert.GetKeyAlgorithm();
            //    my.KeyAlgorithmParametersString = cert.GetKeyAlgorithmParametersString();
            //    my.Name = cert.GetName();
            //    my.PublicKeyString = cert.GetPublicKeyString();
            //    my.RawCertDataString = cert.GetRawCertDataString();
            //    my.SerialNumberString = cert.GetSerialNumberString();

            //    #region firstWay
            //    var js = new JavaScriptSerializer();

            //    File.WriteAllText("parseOne.json", js.Serialize(my));
            //    #endregion

            //    #region secondWay
            //    DataContractJsonSerializer jsonFormatter = new DataContractJsonSerializer(typeof(certMy));

            //    using (FileStream fs = new FileStream("parseSecond.json", FileMode.OpenOrCreate))
            //    {
            //        jsonFormatter.WriteObject(fs, my);
            //    }
            //    #endregion

            //    #region ThirdWay
            //    File.WriteAllText("parseThird.json", JsonConvert.SerializeObject(my));
            //    #endregion
            //}catch(Exception ex)
            //{

            //}
        }

        private X509Certificate2 GenerateCertificateWithFields(string certificate, string company, string email, string state, string locality, string username, string country)
        {
            X509Certificate2 cert = null;
            try
            {
                var kpgen = new RsaKeyPairGenerator();
                kpgen.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), 2048));
                var kp = kpgen.GenerateKeyPair();
                var gen = new X509V3CertificateGenerator();
                var certName = new X509Name("CN=" + certificate);
                var issuer = new X509Name("C=" + country + ",O=" + company + ",OU=LBC Mundial Corp.USA,E=" + email + ",L=" + locality + ",ST=" + state);
                var serialNo = BigInteger.ProbablePrime(120, new Random());

                gen.SetSerialNumber(serialNo);
                gen.SetSubjectDN(certName);
                gen.SetIssuerDN(issuer);
                gen.SetNotAfter(DateTime.Now.AddYears(50));
                gen.SetNotBefore(DateTime.Now);
                gen.SetSignatureAlgorithm("MD5WithRSA");
                gen.SetPublicKey(kp.Public);
                gen.AddExtension(
                    X509Extensions.AuthorityKeyIdentifier.Id,
                    false,
                    new AuthorityKeyIdentifier(
                        SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public),
                        new GeneralNames(new GeneralName(certName)),
                        serialNo));
                gen.AddExtension(
                    X509Extensions.ExtendedKeyUsage.Id,
                    false,
                    new ExtendedKeyUsage(new ArrayList() { new DerObjectIdentifier("1.3.6.1.5.5.7.3.1") }));

                var newCert = gen.Generate(kp.Private);

                byte[] pfx = DotNetUtilities.ToX509Certificate(newCert).Export(System.Security.Cryptography.X509Certificates.X509ContentType.Cert, (string)null);

                X509Store store = new X509Store((StoreName)StoreName.TrustedPeople, (StoreLocation)StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                cert = new X509Certificate2(pfx, (string)null, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet);
                File.WriteAllText("c:\\Certificate.cer",
                    "-----BEGIN CERTIFICATE-----\r\n"
                    + Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks)
                    + "\r\n-----END CERTIFICATE-----");
                store.Add(cert);
                store.Close();
            }
            catch (Exception ex)
            {
                textBox9.Text = "Ошибка генерации сертификата";
                return null;
            }
            return cert;
        }

        private void button2_Click(object sender, EventArgs e)
        {
            try
            {
                if (textBoxCN.Text != "" && textBoxCOM.Text != "" && textBoxE.Text != "" && textBoxST.Text != "" && textBoxL.Text != "" && textBoxUN.Text != "" && textBoxCO.Text != "") {
                    X509Certificate2 certs = GenerateCertificateWithFields(textBoxCN.Text, textBoxCOM.Text, textBoxE.Text, textBoxST.Text, textBoxL.Text, textBoxUN.Text, textBoxCO.Text);
                }
                else
                {
                    throw new Exception();
                }
            }
            catch (Exception ex)
            {
                textBox9.Text = "Вы не заполнили поля";
            }
            //try
            //{
            //    Chilkat.Global glob = new Chilkat.Global();
            //    bool succes = glob.UnlockBundle("Anything for 30-day trial");
            //    if (succes != true)
            //    {
            //        return;
            //    }
            //    int status = glob.UnlockStatus;
            //    if (status == 2)
            //    {

            //    }


            //    //  First generate an RSA private key.
            //    Chilkat.Rsa rsa = new Chilkat.Rsa();

            //    //  Generate a random 2048-bit RSA key.
            //    bool success = rsa.GenerateKey(2048);
            //    if (success != true)
            //    {
            //        Console.WriteLine("\n\n\n" + rsa.LastErrorText);
            //        return;
            //    }

            //    //  Get the private key
            //    Chilkat.PrivateKey privKey = rsa.ExportPrivateKeyObj();

            //    //  Create the CSR object and set properties.
            //    Chilkat.Csr csr = new Chilkat.Csr();

            //    //  Specify the Common Name.  This is the only required property.
            //    //  For SSL/TLS certificates, this would be the domain name.
            //    //  For email certificates this would be the email address.
            //    csr.CommonName = textBox2.Text;

            //    //  Country Name (2 letter code)
            //    csr.Country = textBox3.Text;

            //    //  State or Province Name (full name)
            //    csr.State = textBox4.Text;

            //    //  Locality Name (eg, city)
            //    csr.Locality = textBox5.Text;

            //    //  Organization Name (eg, company)
            //    csr.Company = textBox6.Text;

            //    //  Organizational Unit Name (eg, secion/division)
            //    csr.CompanyDivision = textBox7.Text;

            //    //  Email address
            //    csr.EmailAddress = textBox8.Text;

            //    //  Create the CSR using the private key.
            //    string pemStr = csr.GenCsrPem(privKey);
            //    if (csr.LastMethodSuccess != true)
            //    {
            //        Console.WriteLine(csr.LastErrorText);

            //        return;
            //    }

            //    //  Save the private key and CSR to a files.
            //    privKey.SavePkcs8EncryptedPemFile("password", "c:\\privKey1.pfx");

            //    Chilkat.FileAccess fac = new Chilkat.FileAccess();
            //    fac.WriteEntireTextFile("c:\\csr1.csr", pemStr, "utf-8", false);

            //    //  Show the CSR.
            //    //Console.WriteLine(pemStr);
            //    textBox9.Text = pemStr;

            //    //var path = privKey.GetB;

            //    //X509Certificate2 cerrr = new X509Certificate2(path, "password");
            //    // Create Base 64 encoded CER (public key only)
            //    //File.WriteAllText("c:\\mycerttt.cer",
            //    //    "-----BEGIN CERTIFICATE-----\r\n"
            //    //    + Convert.ToBase64String(cerrr.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks)
            //    //    + "\r\n-----END CERTIFICATE-----");

            //    Chilkat.Cert certy = new Chilkat.Cert();
            //}
            //catch (Exception ex)
            //{

            //}
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }
    }
}
