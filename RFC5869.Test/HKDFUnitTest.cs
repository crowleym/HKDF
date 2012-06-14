using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace RFC5869.Test
{
    /// <summary>
    /// HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
    /// Tests based upon test vecotrs as specificed in RFC: https://tools.ietf.org/html/rfc5869
    /// </summary>
    [TestClass]
    public class HKDFUnitTest
    {
        private TestContext testContextInstance;

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }

        #region Additional test attributes
        //
        // You can use the following additional attributes as you write your tests:
        //
        // Use ClassInitialize to run code before running the first test in the class
        // [ClassInitialize()]
        // public static void MyClassInitialize(TestContext testContext) { }
        //
        // Use ClassCleanup to run code after all tests in a class have run
        // [ClassCleanup()]
        // public static void MyClassCleanup() { }
        //
        // Use TestInitialize to run code before running each test 
        // [TestInitialize()]
        // public void MyTestInitialize() { }
        //
        // Use TestCleanup to run code after each test has run
        // [TestCleanup()]
        // public void MyTestCleanup() { }
        //
        #endregion

        private byte[] Generate(string hex)
        {
            hex = hex.Replace("\r", string.Empty).Replace("\n", string.Empty).Replace("\t", string.Empty).Replace(" ", string.Empty);
            if (hex.StartsWith("0x")) hex = hex.Substring(2);

            int n = hex.Length;
            byte[] buff = new byte[n / 2];
            for (int i = 0; i < n; i += 2)
                buff[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return buff;
        }

        [TestMethod]
        public void Test_Case_1()
        {
            using (var hmac = new HMACSHA256())
            {
                byte[] ikm = Generate("0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                byte[] salt = Generate("0x000102030405060708090a0b0c");
                byte[] info = Generate("0xf0f1f2f3f4f5f6f7f8f9");
                int L = 42;

                byte[] OKM = Generate(@"0x3cb25f25faacd57a90434f64d0362f2a
          2d2d0a90cf1a5a4c5db02d56ecc4c5bf
          34007208d5b887185865");
                
                var hkdf = new HKDF(hmac, ikm, salt);
                var okm = hkdf.Expand(info, L);

                Assert.AreEqual(L, okm.Length);
                Assert.AreEqual(Convert.ToBase64String(OKM), Convert.ToBase64String(okm));

            }
        }

        [TestMethod]
        public void Test_Case_2()
        {
            using (var hmac = new HMACSHA256())
            {
                byte[] ikm = Generate(@"0x000102030405060708090a0b0c0d0e0f
          101112131415161718191a1b1c1d1e1f
          202122232425262728292a2b2c2d2e2f
          303132333435363738393a3b3c3d3e3f
          404142434445464748494a4b4c4d4e4f");
                byte[] salt = Generate(@"0x606162636465666768696a6b6c6d6e6f
          707172737475767778797a7b7c7d7e7f
          808182838485868788898a8b8c8d8e8f
          909192939495969798999a9b9c9d9e9f
          a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
                byte[] info = Generate(@"0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
          c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
          d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
          e0e1e2e3e4e5e6e7e8e9eaebecedeeef
          f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
                int L = 82;

                byte[] OKM = Generate(@"0xb11e398dc80327a1c8e7f78c596a4934
          4f012eda2d4efad8a050cc4c19afa97c
          59045a99cac7827271cb41c65e590e09
          da3275600c2f09b8367793a9aca3db71
          cc30c58179ec3e87c14c01d5c1f3434f
          1d87");

                var hkdf = new HKDF(hmac, ikm, salt);
                var okm = hkdf.Expand(info, L);

                Assert.AreEqual(L, okm.Length);
                Assert.AreEqual(Convert.ToBase64String(OKM), Convert.ToBase64String(okm));

            }
        }

        [TestMethod]
        public void Test_Case_3()
        {
            using (var hmac = new HMACSHA256())
            {
                byte[] ikm = Generate("0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                byte[] salt = Generate(string.Empty);
                byte[] info = Generate(string.Empty);
                int L = 42;

                byte[] OKM = Generate(@"0x8da4e775a563c18f715f802a063c5a31
          b8a11f5c5ee1879ec3454e5f3c738d2d
          9d201395faa4b61a96c8");

                var hkdf = new HKDF(hmac, ikm, salt);
                var okm = hkdf.Expand(info, L);

                Assert.AreEqual(L, okm.Length);
                Assert.AreEqual(Convert.ToBase64String(OKM), Convert.ToBase64String(okm));

            }
        }

        [TestMethod]
        public void Test_Case_4()
        {
            using (var hmac = new HMACSHA1())
            {
                byte[] ikm = Generate("0x0b0b0b0b0b0b0b0b0b0b0b");
                byte[] salt = Generate("0x000102030405060708090a0b0c");
                byte[] info = Generate("0xf0f1f2f3f4f5f6f7f8f9");
                int L = 42;

                byte[] OKM = Generate(@"0x085a01ea1b10f36933068b56efa5ad81
          a4f14b822f5b091568a9cdd4f155fda2
          c22e422478d305f3f896");

                var hkdf = new HKDF(hmac, ikm, salt);
                var okm = hkdf.Expand(info, L);

                Assert.AreEqual(L, okm.Length);
                Assert.AreEqual(Convert.ToBase64String(OKM), Convert.ToBase64String(okm));

            }
        }

        [TestMethod]
        public void Test_Case_5()
        {
            using (var hmac = new HMACSHA1())
            {
                byte[] ikm = Generate(@"0x000102030405060708090a0b0c0d0e0f
          101112131415161718191a1b1c1d1e1f
          202122232425262728292a2b2c2d2e2f
          303132333435363738393a3b3c3d3e3f
          404142434445464748494a4b4c4d4e4f");
                byte[] salt = Generate(@"0x606162636465666768696a6b6c6d6e6f
          707172737475767778797a7b7c7d7e7f
          808182838485868788898a8b8c8d8e8f
          909192939495969798999a9b9c9d9e9f
          a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
                byte[] info = Generate(@"0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf
          c0c1c2c3c4c5c6c7c8c9cacbcccdcecf
          d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
          e0e1e2e3e4e5e6e7e8e9eaebecedeeef
          f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
                int L = 82;

                byte[] OKM = Generate(@"0x0bd770a74d1160f7c9f12cd5912a06eb
          ff6adcae899d92191fe4305673ba2ffe
          8fa3f1a4e5ad79f3f334b3b202b2173c
          486ea37ce3d397ed034c7f9dfeb15c5e
          927336d0441f4c4300e2cff0d0900b52
          d3b4");

                var hkdf = new HKDF(hmac, ikm, salt);
                var okm = hkdf.Expand(info, L);

                Assert.AreEqual(L, okm.Length);
                Assert.AreEqual(Convert.ToBase64String(OKM), Convert.ToBase64String(okm));

            }
        }

        [TestMethod]
        public void Test_Case_6()
        {
            using (var hmac = new HMACSHA1())
            {
                byte[] ikm = Generate("0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
                byte[] salt = Generate(string.Empty);
                byte[] info = Generate(string.Empty);
                int L = 42;

                byte[] OKM = Generate(@"0x0ac1af7002b3d761d1e55298da9d0506
          b9ae52057220a306e07b6b87e8df21d0
          ea00033de03984d34918");

                var hkdf = new HKDF(hmac, ikm, salt);
                var okm = hkdf.Expand(info, L);

                Assert.AreEqual(L, okm.Length);
                Assert.AreEqual(Convert.ToBase64String(OKM), Convert.ToBase64String(okm));

            }
        }

        [TestMethod]
        public void Test_Case_7()
        {
            using (var hmac = new HMACSHA1())
            {
                byte[] ikm = Generate("0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
                byte[] salt = null;
                byte[] info = Generate(string.Empty);
                int L = 42;

                byte[] OKM = Generate(@"0x2c91117204d745f3500d636a62f64f0a
          b3bae548aa53d423b0d1f27ebba6f5e5
          673a081d70cce7acfc48");

                var hkdf = new HKDF(hmac, ikm, salt);
                var okm = hkdf.Expand(info, L);

                Assert.AreEqual(L, okm.Length);
                Assert.AreEqual(Convert.ToBase64String(OKM), Convert.ToBase64String(okm));

            }
        }
    }
}
