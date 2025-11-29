// const container = document.getElementById('container');
// const registerBtn = document.getElementById('register');
// const loginBtn = document.getElementById('login');

// registerBtn.addEventListener('click', () => {
//     container.classList.add("active");
// });

// loginBtn.addEventListener('click', () => {
//     container.classList.remove("active");
// });

// async function save() {
//     const domain = document.getElementById("domain").value;
//     const password = document.getElementById("password").value;

//     const res = await fetch("http://127.0.0.1:5500/set", {
//         method: "POST",
//         headers: { "Content-Type": "application/json" },
//         body: JSON.stringify({ domain, value: password })
//     });

//     const data = await res.json();
//     alert(data.message);
// }


const container = document.getElementById("container");

// Toggle between signup/signin panels
document.getElementById("register").addEventListener("click", () => {
    container.classList.add("active");
});

document.getElementById("login").addEventListener("click", () => {
    container.classList.remove("active");
});

// Handle Signup
document.querySelector(".sign-up form").addEventListener("submit", async (e) => {
    e.preventDefault();

    const email = e.target.querySelector('input[type="email"]').value;
    const password = e.target.querySelector('input[type="password"]').value;

    try {
        const res = await fetch("/signup", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password }),
        });

        const data = await res.json();
        console.log("Signup response:", data);                     // Debug
        alert(data.message);                                       // UI feedback

        if (res.ok) {
            console.log("Current users database (TEMP):", window.usersDebug);
            container.classList.remove("active"); // Switch to login panel
        }
    } catch (err) {
        console.error("Signup error:", err);
    }
});

// Handle Signin
document.querySelector(".sign-in form").addEventListener("submit", async (e) => {
    e.preventDefault();

    const email = e.target.querySelector('input[type="email"]').value;
    const password = e.target.querySelector('input[type="password"]').value;

    try {
        const res = await fetch("/signin", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email, password }),
        });

        const data = await res.json();
        console.log("Signin response:", data);                    // Debug
        alert(data.message);                                      // UI feedback

        if (res.ok) {
            console.log("Current users database (TEMP):", window.usersDebug);
            // redirect or show dashboard later
        }
    } catch (err) {
        console.error("Signin error:", err);
    }
});
