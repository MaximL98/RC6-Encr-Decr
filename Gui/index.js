

document.getElementById('encrypt-button').addEventListener('click', async function () {
  // Add styling of longer than 20 strings- for long keys
  addStyleToHeadForTruncatedText();

  // Clear output block
  while (document.getElementById('output').firstChild) {
    document.getElementById('output').removeChild(document.getElementById('output').firstChild);
  }

  // Animation code:
  const dotContainer = document.querySelector('.passing-dots1');
  const dotCount = 6;
  const dotDuration = 2000; // Each dot appears for 0.5 seconds
  const delayBetweenDots = 150;
  for (let i = dotCount; i > 0; i--) {
    setTimeout(() => {
      const dot = document.createElement('div');
      dot.classList.add('dot');
      dotContainer.appendChild(dot);

      setTimeout(() => dot.remove(), dotDuration);
    }, i * delayBetweenDots);
  }

  setTimeout(() => {
    for (let i = dotCount; i > 0; i--) {
      setTimeout(() => {
        const dot = document.createElement('div');
        dot.classList.add('dot');
        dotContainer.appendChild(dot);

        setTimeout(() => dot.remove(), dotDuration);
      }, i * delayBetweenDots);
    }
  }, 2750);

  setTimeout(() => {
    for (let i = dotCount; i > 0; i--) {
      setTimeout(() => {
        const dot = document.createElement('div');
        dot.classList.add('dot');
        dotContainer.appendChild(dot);

        setTimeout(() => dot.remove(), dotDuration);
      }, i * delayBetweenDots);
    }
  }, 5500);


  // Get input values
  const cardNumber = document.getElementById('card-number').value;
  const name = document.getElementById('name').value;
  const passcode = document.getElementById('passcode').value;
  const cvc = document.getElementById('cvc').value;

  console.log(cvc);

  // Perform encryption (you'll need a suitable encryption library)
  // Example using a simple placeholder, not secure!


  // Update output block
  outputElement = document.getElementById('output');
  bankElement = document.getElementById('bank');

  //document.getElementById('passing-dots').style.display = "block";


  // Display message to send
  const sentenceLine = document.createElement('p');
  sentenceLine.style.margin = "5px";
  sentenceLine.style.color = "green";
  sentenceLine.style.textDecoration = "underline";

  const sentenceToSend = await getPublicKeyData("SentenceToSend")
  const sentenceShortened = createTruncatedTextElement(sentenceToSend.sentence, 35);

  setTimeout(() => outputElement.appendChild(sentenceLine), 500);
  setTimeout(() => sentenceLine.textContent = "Requested message to encrypt:", 500);
  setTimeout(() => outputElement.appendChild(sentenceShortened), 500);

  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // Display the secret keys created by the user
  const secretKey1Line = document.createElement('p');
  secretKey1Line.style.margin = "5px";
  secretKey1Line.style.color = "green";
  secretKey1Line.style.textDecoration = "underline";

  const secretKey2Line = document.createElement('p');
  secretKey2Line.style.margin = "5px";
  secretKey2Line.style.color = "green";
  secretKey2Line.style.textDecoration = "underline";

  const schnorrKeyLine = document.createElement('p');
  schnorrKeyLine.style.margin = "5px";
  schnorrKeyLine.style.color = "green";
  schnorrKeyLine.style.textDecoration = "underline";

  const secretKeys = await getPublicKeyData("SecretKeys")
  const secretKey1Shortened = createTruncatedTextElement(secretKeys.secret1, 35);
  const secretKey2Shortened = createTruncatedTextElement(secretKeys.secret2, 35);
  const schnorrKeyShortened = createTruncatedTextElement(secretKeys.sch_key, 35);

  // Secret key 1:
  setTimeout(() => outputElement.appendChild(secretKey1Line), 1500);
  setTimeout(() => secretKey1Line.textContent = "Generated secret key 1:", 1500);
  setTimeout(() => outputElement.appendChild(secretKey1Shortened), 1500);

  // Secret key 2:
  setTimeout(() => outputElement.appendChild(secretKey2Line), 2500);
  setTimeout(() => secretKey2Line.textContent = "Generated secret Key 2:", 2500);
  setTimeout(() => outputElement.appendChild(secretKey2Shortened), 2500);

  // Schnorr key:
  setTimeout(() => outputElement.appendChild(schnorrKeyLine), 3500);
  setTimeout(() => schnorrKeyLine.textContent = "Generated Schnorr key:", 3500);
  setTimeout(() => outputElement.appendChild(schnorrKeyShortened), 3500);

  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // Display the encrypted message using the secret keys

  const encryptedMessageLine = document.createElement('p');
  encryptedMessageLine.style.margin = "5px";
  encryptedMessageLine.style.color = "green";
  encryptedMessageLine.style.textDecoration = "underline";

  const encryptedMessage = await getPublicKeyData("EncryptedSentence")
  const encryptedMessageShortened = createTruncatedTextElement(encryptedMessage.EncryptedSentence.slice(3, encryptedMessage.EncryptedSentence.length - 2), 50);

  setTimeout(() => outputElement.appendChild(encryptedMessageLine), 4500);
  setTimeout(() => encryptedMessageLine.textContent = "Encrypted message:", 4500);
  setTimeout(() => outputElement.appendChild(encryptedMessageShortened), 4500);

  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // Display the hash digest of the encrypted message
  const hashDigestLine = document.createElement('p');
  hashDigestLine.style.margin = "5px";
  hashDigestLine.style.color = "green";
  hashDigestLine.style.textDecoration = "underline";
  const privateKeyAsHexLine = document.createElement('p');
  privateKeyAsHexLine.style.margin = "5px";
  privateKeyAsHexLine.style.color = "green";
  privateKeyAsHexLine.style.textDecoration = "underline";

  const hashDigest = await getPublicKeyData("Schnorr_get_message_digest")
  const hashDigestShortened = createTruncatedTextElement(hashDigest.message_hash_digest, 35);
  const privateKeyAsHexShortened = createTruncatedTextElement(hashDigest.private_key_as_hex_string, 35);

  setTimeout(() => outputElement.appendChild(hashDigestLine), 5500);
  setTimeout(() => hashDigestLine.textContent = "Hash digest of the encrypted message:", 5500);
  setTimeout(() => outputElement.appendChild(hashDigestShortened), 5500);

  setTimeout(() => outputElement.appendChild(privateKeyAsHexLine), 6500);
  setTimeout(() => privateKeyAsHexLine.textContent = "Private key as hex string:", 6500);
  setTimeout(() => outputElement.appendChild(privateKeyAsHexShortened), 6500);

  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // Display Schnor signature of the encrypted message using the private key
  const signatureLine = document.createElement('p');
  signatureLine.style.margin = "5px";
  signatureLine.style.color = "green";
  signatureLine.style.textDecoration = "underline";

  const signature = await getPublicKeyData("Schnorr_sign_via_private_key")
  const signatureShortened = createTruncatedTextElement(signature.Signature, 35);

  setTimeout(() => outputElement.appendChild(signatureLine), 7500);
  setTimeout(() => signatureLine.textContent = "Generated Schnorr signature:", 7500);
  setTimeout(() => outputElement.appendChild(signatureShortened), 7500);

  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // Display the public key used for the signature
  const publicKeyLine = document.createElement('p');
  publicKeyLine.style.margin = "5px";
  publicKeyLine.style.color = "green";
  publicKeyLine.style.textDecoration = "underline";

  const publicKey = await getPublicKeyData("Public_Key")
  const publicKeyShortened = createTruncatedTextElement(publicKey.public_key, 35);

  setTimeout(() => outputElement.appendChild(publicKeyLine), 8500);
  setTimeout(() => publicKeyLine.textContent = "Public key used for the signature:", 8500);
  setTimeout(() => outputElement.appendChild(publicKeyShortened), 8500);


  const blankLine = document.createElement('p');
  blankLine.style.margin = "5px";
  blankLine.style.color = "green";
  blankLine.style.textDecoration = "underline";
  blankLine.textContent = " ";

  setTimeout(() => outputElement.appendChild(blankLine), 9000);

  setTimeout(() => {
    document.getElementById('bankButton').style.backgroundColor = "green";
    document.getElementById('bankButton').textContent = "Send to Bank";
  }, 9000);

});

// Send the encrypted message and the signature to the bank, with the public key
document.getElementById('bankButton').addEventListener('click', async function () {

  // Animation code:
  const dotContainer = document.querySelector('.passing-dots2');
  const dotCount = 6;
  const dotDuration = 1000; // Each dot appears for 0.5 seconds
  const delayBetweenDots = 150;
  for (let i = dotCount; i > 0; i--) {
    setTimeout(() => {
      const dot = document.createElement('div');
      dot.classList.add('dot');
      dotContainer.appendChild(dot);

      setTimeout(() => dot.remove(), dotDuration);
    }, i * delayBetweenDots);
  }

  setTimeout(() => {
    for (let i = dotCount; i > 0; i--) {
      setTimeout(() => {
        const dot = document.createElement('div');
        dot.classList.add('dot');
        dotContainer.appendChild(dot);

        setTimeout(() => dot.remove(), dotDuration);
      }, i * delayBetweenDots);
    }
  }, 2000);

  const bankMessageLine = document.createElement('p');
  bankMessageLine.style.margin = "5px";
  bankMessageLine.style.color = "green";
  bankMessageLine.style.textDecoration = "underline";

  const encryptedMessage = await getPublicKeyData("EncryptedSentence")
  const encryptedMessageShortened = createTruncatedTextElement(encryptedMessage.EncryptedSentence.slice(3, encryptedMessage.EncryptedSentence.length - 2), 50);


  setTimeout(() => bankElement.appendChild(bankMessageLine), 500);
  setTimeout(() => bankMessageLine.textContent = "Message received:", 500);
  setTimeout(() => bankElement.appendChild(encryptedMessageShortened), 500);

  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // Display the signature received from the user

  const signatureReceivedLine = document.createElement('p');
  signatureReceivedLine.style.margin = "5px";
  signatureReceivedLine.style.color = "green";
  signatureReceivedLine.style.textDecoration = "underline";

  const signatureReceived = await getPublicKeyData("Schnorr_sign_via_private_key")
  const signatureReceivedShortened = createTruncatedTextElement(signatureReceived.Signature, 35);

  setTimeout(() => bankElement.appendChild(signatureReceivedLine), 1500);
  setTimeout(() => signatureReceivedLine.textContent = "Signature received:", 1500);
  setTimeout(() => bankElement.appendChild(signatureReceivedShortened), 1500);

  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // Display the public key received from the user
  const publicKeyReceivedLine = document.createElement('p');
  publicKeyReceivedLine.style.margin = "5px";
  publicKeyReceivedLine.style.color = "green";
  publicKeyReceivedLine.style.textDecoration = "underline";

  const publicKey = await getPublicKeyData("Public_Key")
  const publicKeyShortened = createTruncatedTextElement(publicKey.public_key, 35);

  setTimeout(() => bankElement.appendChild(publicKeyReceivedLine), 2500);
  setTimeout(() => publicKeyReceivedLine.textContent = "Public key received:", 2500);
  setTimeout(() => bankElement.appendChild(publicKeyShortened), 2500);

  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // Decode the encrypted message using the public key and verify the signature
  const decodedMessageLine = document.createElement('p');
  decodedMessageLine.style.margin = "5px";
  decodedMessageLine.style.color = "green";
  decodedMessageLine.style.textDecoration = "underline";

  const decodedMessage = await getPublicKeyData("SentenceToSend")
  const decodedMessageShortened = createTruncatedTextElement(decodedMessage.sentence, 50);

  const checkingSignature = createTruncatedTextElement("Checking signature...", 50);
  const preparingPublicKey = createTruncatedTextElement("Preparing public key...", 50);
  const decryptingMessage = createTruncatedTextElement("Decrypting message...", 50);
  const success = createTruncatedTextElement("Success!", 50);
  success.style.color = "green";

  setTimeout(() => bankElement.appendChild(checkingSignature), 3500);
  setTimeout(() => bankElement.appendChild(preparingPublicKey), 4500);
  setTimeout(() => bankElement.appendChild(decryptingMessage), 5500);
  setTimeout(() => bankElement.appendChild(success), 6500);


  setTimeout(() => bankElement.appendChild(decodedMessageLine), 7000);
  setTimeout(() => decodedMessageLine.textContent = "Decoded message:", 7000);
  setTimeout(() => bankElement.appendChild(decodedMessageShortened), 7000);

  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  setTimeout(() => {
    document.getElementById('successButton').style.backgroundColor = "blue";
    document.getElementById('successButton').textContent = "Send \"Success\" to User";
  }, 7500);

  // Send an encoded "Success" message to the user
  const successMessageLine = document.createElement('p');
  successMessageLine.style.margin = "5px";
  successMessageLine.style.color = "red";

  document.getElementById('bankButton').classList.add('sendToUser');
});


document.getElementById('successButton').addEventListener('click', async function () {
  // Clear output block
  while (document.getElementById('output').firstChild) {
    document.getElementById('output').removeChild(document.getElementById('output').firstChild);
  }

  document.getElementById('bankButton').style.backgroundColor = "transparent";
  document.getElementById('bankButton').textContent = "";

  // Animation code:
  const dotContainer = document.querySelector('.passing-dots2');
  const dotCount = 6;
  const dotDuration = 1000; // Each dot appears for 0.5 seconds
  const delayBetweenDots = 150;
  for (let i = dotCount; i > 0; i--) {
    setTimeout(() => {
      const dot = document.createElement('div');
      dot.classList.add('dot');
      dotContainer.appendChild(dot);

      setTimeout(() => dot.remove(), dotDuration);
    }, i * delayBetweenDots);
  }

  setTimeout(() => {
    for (let i = dotCount; i > 0; i--) {
      setTimeout(() => {
        const dot = document.createElement('div');
        dot.classList.add('dot');
        dotContainer.appendChild(dot);

        setTimeout(() => dot.remove(), dotDuration);
      }, i * delayBetweenDots);
    }
  }, 2000);

  const encryptionSuccessMessageLine = document.createElement('p');
  encryptionSuccessMessageLine.style.margin = "5px";
  encryptionSuccessMessageLine.style.color = "green";

  setTimeout(() => document.getElementById('output').appendChild(encryptionSuccessMessageLine), 500);
  setTimeout(() => encryptionSuccessMessageLine.textContent = "Encoding \"Success\" message to user", 500);

  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // Encrypt the "Success" message using the public key, and send it to the user
  const encryptingMessage = createTruncatedTextElement("Encrypted message:", 50);
  const encryptedSuccess = createTruncatedTextElement("SOME ENCRYPTED MESSAGE !@$!@#$#$ygheatr", 50);
  encryptingMessage.style.color = "green";

  setTimeout(() => document.getElementById('output').appendChild(encryptingMessage), 1500);
  setTimeout(() => document.getElementById('output').appendChild(encryptedSuccess), 1500);

  // Send the encoded "Success" message to the user
  const successMessageLine = document.createElement('p');
  successMessageLine.style.margin = "5px";
  successMessageLine.style.color = "green";
  successMessageLine.style.textDecoration = "underline";

  setTimeout(() => document.getElementById('output').appendChild(successMessageLine), 2500);

  setTimeout(() => {
    document.getElementById("sendToUser").style.backgroundColor = "green";
    document.getElementById("sendToUser").textContent = "Send to User";
  }, 3500);

});

document.getElementById("sendToUser").addEventListener('click', async function () {
  // Animation code:
  const dotContainer = document.querySelector('.passing-dots1');
  const dotCount = 6;
  const dotDuration = 1000; // Each dot appears for 0.5 seconds
  const delayBetweenDots = 150;
  for (let i = dotCount; i > 0; i--) {
    setTimeout(() => {
      const dot = document.createElement('div');
      dot.classList.add('dot');
      dotContainer.appendChild(dot);

      setTimeout(() => dot.remove(), dotDuration);
    }, i * delayBetweenDots);
  }

  const userMessageLine = document.createElement('p');
  userMessageLine.style.margin = "5px";
  userMessageLine.style.color = "green";

  setTimeout(() => document.getElementById('user').appendChild(userMessageLine), 500);
  setTimeout(() => userMessageLine.textContent = "Successfully paid!", 1500);

});

async function getPublicKeyData(fileName) {
  fileName = './JSONFiles/' + fileName + ".json";
  try {
    const response = await fetch(fileName);
    const data = await response.json();
    // Use publicKeyData here
    return data;
  } catch (error) {
    console.error("Error fetching public key file:", error);
  }
}

function createTruncatedTextElement(text, maxLength) {
  const span = document.createElement('p');
  span.style.margin = "5px";
  shortenedText = createShortText(text, maxLength);

  if (text.length > maxLength) {
    span.textContent = shortenedText; // Set the shortened text as content
    span.title = text; // Set the full text as hover text
    span.classList.add('truncated'); // Add a class for styling
  }
  else {
    span.textContent = text;
  }
  return span;
}

function createShortText(text, maxLength) {
  if (text.length > maxLength) {
    return text.slice(0, maxLength) + '...';
  }
  return text;
}

function addStyleToHeadForTruncatedText() {
  const style = document.createElement('style');
  style.textContent = `
  .truncated {
    display: inline-block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    cursor: help; /* Change cursor on hover */
    height: 15px;
    margin: 0px;
    padding: 0px;
    text-decoration: underline; /* Reset default underline */
  }

  .truncated:hover {
    text-decoration: underline; /* Apply underline on hover */
  }
`;
  document.head.appendChild(style);
}