const container = document.getElementById('container');
const registerBtn = document.getElementById('register');
const loginBtn = document.getElementById('login');

registerBtn.addEventListener('click', () => {
    container.classList.add("active");
});

loginBtn.addEventListener('click', () => {
    container.classList.remove("active");
});

async function save() {
    const domain = document.getElementById("domain").value;
    const password = document.getElementById("password").value;

    const res = await fetch("http://127.0.0.1:5500/set", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, value: password })
    });

    const data = await res.json();
    alert(data.message);
}
