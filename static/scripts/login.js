document
    .getElementById("update-info-form")
    .addEventListener("submit", async (e) => {
        e.preventDefault();

        const payload = {
            email: document.getElementById("update-info-email").value,
            password: document.getElementById("update-info-pw").value,
        };

        let response;
        try {
            response = await fetch("/api/users", {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(payload),
            });
        } catch (err) {
            console.log(`Failed to update info: ${err}`);
            return;
        }

        if (response.status === 401) {
            let refreshResponse;
            try {
                refreshResponse = await fetch("/api/refresh", {
                    method: "POST",
                });
            } catch (err) {
                console.log(`Failed to used refresh token: ${err}`);
                return;
            }

            try {
                response = await fetch("/api/users", {
                    method: "PUT",
                    headers: {
                        "Content-Type": "application/json",
                    },
                    body: JSON.stringify(payload),
                });
            } catch (err) {
                console.log(`Failed to update info AGAIN: ${err}`);
                return;
            }
        }

        if (response.status === 401) {
            console.log(`unathorized again, logout now`);
            return;
        }

        console.log(`Info updated with: ${payload.email}: ${payload.password}`);
    });
