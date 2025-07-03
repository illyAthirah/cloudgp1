document.getElementById('authForm').addEventListener('submit', async function(event) {
    event.preventDefault(); // Prevent default form submission

    const form = event.target;
    const formData = new FormData(form);
    const resultDiv = document.getElementById('result');

    resultDiv.innerHTML = 'Authenticating...';
    resultDiv.className = ''; // Clear previous styling

    try {
        const response = await fetch('/authenticate', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();

        resultDiv.innerHTML = data.message;
        resultDiv.classList.add(data.status); // Add success or error class
    } catch (error) {
        console.error('Error during authentication:', error);
        resultDiv.innerHTML = 'An error occurred during simulation. Please try again.';
        resultDiv.classList.add('error');
    }
});