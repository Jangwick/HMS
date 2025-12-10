document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('password');
    const submitButton = document.querySelector('button[type="submit"]');
    
    if (!passwordInput) return;

    // Create validation message container
    const messageContainer = document.createElement('div');
    messageContainer.className = 'mt-2 text-sm space-y-1 hidden';
    messageContainer.id = 'password-requirements';
    passwordInput.parentNode.parentNode.appendChild(messageContainer);

    const requirements = [
        { regex: /.{8,}/, text: "At least 8 characters" },
        { regex: /[A-Z]/, text: "At least one uppercase letter" },
        { regex: /[a-z]/, text: "At least one lowercase letter" },
        { regex: /[0-9]/, text: "At least one number" },
        { regex: /[!@#$%^&*(),.?":{}|<>]/, text: "At least one special character" }
    ];

    passwordInput.addEventListener('focus', () => {
        messageContainer.classList.remove('hidden');
    });

    passwordInput.addEventListener('input', () => {
        const password = passwordInput.value;
        let allValid = true;
        
        messageContainer.innerHTML = ''; // Clear previous messages

        requirements.forEach(req => {
            const isValid = req.regex.test(password);
            const item = document.createElement('div');
            item.className = 'flex items-center';
            
            const icon = document.createElement('i');
            icon.className = `bi ${isValid ? 'bi-check-circle-fill text-green-500' : 'bi-circle text-gray-400'} mr-2`;
            
            const text = document.createElement('span');
            text.className = isValid ? 'text-green-600' : 'text-gray-500';
            text.textContent = req.text;
            
            item.appendChild(icon);
            item.appendChild(text);
            messageContainer.appendChild(item);

            if (!isValid) allValid = false;
        });

        // Optional: Disable submit if requirements not met (for registration/change password)
        // For login, we usually let the backend handle it to avoid leaking policy info too aggressively,
        // but for a "Change Password" or "New User" flow, this is critical.
        // For this specific request, I'll leave the button active but show indicators.
    });
});
