using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;

namespace Decaptcher.Test
{
    [TestClass]
    public class DecaptcherTest
    {
        private string _username;
        private string _password;
        private int _port;

        [TestInitialize]
        public void Initialize()
        {
            var credentials = File.ReadAllText("../../../credentials.txt");
            var parts = credentials.Split(':');
            _username = parts[0];
            _password = parts[1];
            _port = int.Parse(parts[2]);
        }

        [TestMethod]
        public void TestLogin()
        {
            var client = new CCProto();
            Assert.AreNotEqual(APIConstants.ccERR_OK, client.Login("api.decaptcher.com", _port, string.Empty, string.Empty));
            Assert.AreEqual(APIConstants.ccERR_OK, client.Login("api.decaptcher.com", _port, _username, _password));
            Assert.AreEqual(APIConstants.ccERR_OK, client.Close());
        }

        [TestMethod]
        public void TestCheckBalance()
        {
            var client = new CCProto();
            Assert.AreEqual(APIConstants.ccERR_OK, client.Login("api.decaptcher.com", _port, _username, _password));
            var balance = client.GetBalance();
            Assert.AreEqual(APIConstants.ccERR_OK, balance.ReturnCode);
            Assert.IsTrue(double.Parse(balance.Balance) > 0);
            Assert.AreEqual(APIConstants.ccERR_OK, client.Close());
        }

        [TestMethod]
        public void TestDecodeCaptcha()
        {
            var client = new CCProto();
            Assert.AreEqual(APIConstants.ccERR_OK, client.Login("api.decaptcher.com", _port, _username, _password));
            var result = client.picture2(File.ReadAllBytes("../../../sample.png"), 30, (int)PictureType.Unspecified);
            Assert.AreEqual(APIConstants.ccERR_OK, result.returnCode);
            Assert.AreEqual("3sqb7u7", result.text.ToLowerInvariant());
            Assert.AreEqual(APIConstants.ccERR_OK, client.Close());
        }
    }
}
