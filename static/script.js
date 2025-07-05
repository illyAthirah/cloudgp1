document.getElementById('authForm').addEventListener('submit', async function(event) {
    event.preventDefault();

    const form = event.target;
    const formData = new FormData(form);
    const resultDiv = document.getElementById('result');

    resultDiv.innerHTML = 'Authenticating...';
    resultDiv.className = ''; // Clear previous classes

    try {
        const response = await fetch('/authenticate', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            // Handle HTTP errors (e.g., 500 server error)
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        console.log("Response data from /authenticate:", data);

        resultDiv.innerHTML = data.message || ''; // Display message from backend
        resultDiv.classList.add(data.status); // Add status class (success/error)

        if (data.status === 'mfa_required' && data.redirect) {
            console.log("Redirecting to MFA verification:", data.redirect);
            window.location.href = data.redirect; // Redirect to MFA verification page
            return;
        }

        // This part might not be needed if all successful local logins go through MFA,
        // but it's good to have for other success cases.
        if (data.status === 'success' && data.redirect) {
            setTimeout(() => {
                window.location.href = data.redirect;
            }, 1500); // Redirect to dashboard after a short delay
        }

    } catch (error) {
        console.error('Error during authentication:', error);
        resultDiv.innerHTML = 'An error occurred. Please try again.';
        resultDiv.classList.add('error');
    }
});