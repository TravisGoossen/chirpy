document.getElementById("registration-form").addEventListener("submit", async (e) => {
    e.preventDefault();

    const payload = {
        email: document.getElementById("registration-email").value,
        password: document.getElementById("registration-password").value,
    }

    const response = await fetch("/api/users/test", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
    });

    console.log(response)
});

document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();

    const payload = {
        email: document.getElementById("login-email").value,
        password: document.getElementById("login-password").value,
    }
    	
    const response = await fetch("/api/login", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
    });

    const result = await response.json();

    if (result.redirect) {
        window.location.href = result.redirect;
    }
});