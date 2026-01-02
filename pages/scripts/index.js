document
    .getElementById("registration-form")
    .addEventListener("submit", async (e) => {
        e.preventDefault();

        const payload = {
            email: document.getElementById("registration-email").value,
            password: document.getElementById("registration-password").value,
        };

        try {
            const response = await fetch("/api/users/test", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
            });

            if (!response.ok) {
                const errorText = response.text();
                console.log(errorText);
                return;
            }
            console.log(
                `Registered with: ${payload.email}: ${payload.password}`
            );
        } catch (err) {
            console.log(`registration failed: ${err}`);
            return;
        }
    });

document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();

    const payload = {
        email: document.getElementById("login-email").value,
        password: document.getElementById("login-password").value,
    };

    try {
        const response = await fetch("/api/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.log(errorText);
            return;
        }

        const result = await response.json();
        console.log(`Logged in as: ${payload.email}`);

        window.location.href = "/app/login.html";
    } catch (err) {
        console.log(`login failed: ${err}`);
        return;
    }
});
