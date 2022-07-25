// Configure your import map in config/importmap.rb. Read more: https://github.com/rails/importmap-rails
import "@hotwired/turbo-rails"
import "controllers"

let result = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()

if (result === true) {
  navigator.credentials.create({
    publicKey: {
      rp: {
        name: "test-fido",
        id: "test-fido.herokuapp.com",
      },
      user: {
        id: new Uint8Array(16),
        name: "jdoe@example.com",
        displayName: "John Doe"
      },
      challenge: "123456",
      publicKeyCredParams: {
        type: "public-key",
        alg: -7
      },
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        userVerification: "required"
      }
    }
  }).then(function (newCredentialInfo) {
    var response = newCredentialInfo.response;
    var clientExtensionsResults = newCredentialInfo.getClientExtensionResults();
    alert(clientExtensionsResults);
  }).catch(function (err) {
    alert(err);
  });
} else {
  alert("No FIDO support")
}
