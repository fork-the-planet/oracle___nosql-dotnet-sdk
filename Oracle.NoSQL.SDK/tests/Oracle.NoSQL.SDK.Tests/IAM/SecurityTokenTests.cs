/*-
 * Copyright (c) 2020, 2025 Oracle and/or its affiliates. All rights reserved.
 *
 * Licensed under the Universal Permissive License v 1.0 as shown at
 *  https://oss.oracle.com/licenses/upl/
 */

namespace Oracle.NoSQL.SDK.Tests.IAM
{
    using System;
    using System.Security.Cryptography;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using static TestData;
    using static Utils;

    [TestClass]
    public class SecurityTokenTests
    {
        [TestMethod]
        public void TestSecurityTokenValidatesMatchingPublicKey()
        {
            var token = SecurityToken.Create(CreateSecurityToken(Keys.RSA));

            token.ValidatePublicKey(Keys.RSA);
        }

        [TestMethod]
        public void TestSecurityTokenRejectsMismatchedPublicKey()
        {
            using var otherKey = RSA.Create(2048);
            var token = SecurityToken.Create(CreateSecurityToken(Keys.RSA));

            Assert.ThrowsException<ArgumentException>(() =>
                token.ValidatePublicKey(otherKey));
        }

        [TestMethod]
        public void TestSecurityTokenRejectsMissingJWK()
        {
            var token = SecurityToken.Create(CreateSecurityToken(Keys.RSA,
                includeJWK: false));

            Assert.ThrowsException<ArgumentException>(() =>
                token.ValidatePublicKey(Keys.RSA));
        }

        [TestMethod]
        public void TestSecurityTokenDetectsExpiredToken()
        {
            var token = SecurityToken.Create(CreateSecurityToken(Keys.RSA,
                TimeSpan.FromMinutes(-1)));

            Assert.IsFalse(token.IsValid());
        }

        [TestMethod]
        public async Task TestInvalidRefreshedTokenIsNotCached()
        {
            var provider = new TestSecurityTokenBasedProvider(
                CreateSecurityTokenWithNewKey());

            await Assert.ThrowsExceptionAsync<ArgumentException>(() =>
                provider.GetProfileAsync(true, CancellationToken.None));

            await Assert.ThrowsExceptionAsync<ArgumentException>(() =>
                provider.GetProfileAsync(false, CancellationToken.None));

            Assert.AreEqual(2, provider.RefreshCount);
        }

        [TestMethod]
        public async Task TestInvalidForcedRefreshDoesNotReplaceCachedToken()
        {
            var validToken = CreateSecurityToken(Keys.RSA);
            var invalidToken = CreateSecurityTokenWithNewKey();
            var provider = new TestSecurityTokenBasedProvider(
                validToken, invalidToken);

            var profile = await provider.GetProfileAsync(true,
                CancellationToken.None);
            Assert.AreEqual(GetKeyIdFromToken(validToken), profile.KeyId);

            await Assert.ThrowsExceptionAsync<ArgumentException>(() =>
                provider.GetProfileAsync(true, CancellationToken.None));

            profile = await provider.GetProfileAsync(false,
                CancellationToken.None);
            Assert.AreEqual(GetKeyIdFromToken(validToken), profile.KeyId);
            Assert.AreEqual(2, provider.RefreshCount);
        }

        private class TestSecurityTokenBasedProvider :
            SecurityTokenBasedProvider
        {
            private readonly string[] tokens;

            internal TestSecurityTokenBasedProvider(params string[] tokens) :
                base(TimeSpan.Zero)
            {
                this.tokens = tokens;
            }

            internal int RefreshCount { get; private set; }

            private protected override RSA PrivateKey => Keys.RSA;

            private protected override Task<string> RefreshSecurityTokenAsync(
                CancellationToken cancellationToken)
            {
                var token = tokens[Math.Min(RefreshCount,
                    tokens.Length - 1)];
                RefreshCount++;
                return Task.FromResult(token);
            }

            protected override void Dispose(bool disposing)
            {
            }
        }
    }
}
