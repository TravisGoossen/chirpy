document
    .getElementById("update-info-form")
    .addEventListener("submit", async (e) => {
        e.preventDefault();

        const payload = {
            email: document.getElementById("update-info-email").value,
            newPassword: document.getElementById("update-info-pw").value,
        };
        console.log(payload);
        const response = await fetch("/api/users", {
            method: "PUT",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(payload),
        });

        // add a try/catch to this, change the endpoint in go to use cookies instead of header
        // probably can delete the test endpoints and alter the previous endpoints to use cookies instead of headers

        // console.log("info updated");
    });
