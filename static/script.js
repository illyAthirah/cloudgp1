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

        // ✅ Redirect to dashboard if login is successful
        if (data.status === 'success' && data.redirect) {
            setTimeout(() => {
                window.location.href = data.redirect;
            }, 1500); // 1.5 second delay to show message
        }

    } catch (error) {
        console.error('Error during authentication:', error);
        resultDiv.innerHTML = 'An error occurred during simulation. Please try again.';
        resultDiv.classList.add('error');
    }
});

document.addEventListener('DOMContentLoaded', function() {
    // Only run on dashboard
    if (document.querySelector('.dashboard')) {
        const loginTime = new Date();
        const loginTimeElement = document.getElementById('login-time');
        const durationElement = document.getElementById('session-duration');

        // Format login time
        if (loginTimeElement) {
            loginTimeElement.textContent = loginTime.toLocaleTimeString();
        }

        // Update session duration every minute
        if (durationElement) {
            setInterval(() => {
                const now = new Date();
                const diffMs = now - loginTime;
                const diffMins = Math.round(diffMs / 60000);
                durationElement.textContent = `${diffMins} minutes`;
            }, 60000);
        }
    }
});
