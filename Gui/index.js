document.getElementById('encrypt-button').addEventListener('click', function() {
    // 1. Get input values
    const cardNumber = document.getElementById('card-number').value;
    const name = document.getElementById('name').value;
    const passcode = document.getElementById('passcode').value;
    const cvc = document.getElementById('cvc').value;

    // 2. Perform encryption (you'll need a suitable encryption library)
    //    Example using a simple placeholder, not secure!
    const encryptedData = "Placeholder: " + cardNumber + " - " + name; 

    // 3. Update output block
    document.getElementById('output').textContent = encryptedData;
});


// Fetch data from the server
fetch("http://localhost:8000/test") // Replace with your endpoint
  .then(response => response.text())
  .then(data => {
    console.log(data); // Output: "Hello World!" (if your Python script returns the string)
  })
  .catch(error => console.error(error));