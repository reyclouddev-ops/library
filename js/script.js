const loginForm = document.getElementById("loginForm");
const loginMessage = document.getElementById("loginMessage");

if (loginForm) {
  loginForm.addEventListener("submit", async event => {
    event.preventDefault();

    const username = document
      .getElementById("loginUsername")
      .value
      .trim();

    const password = document
      .getElementById("loginPassword")
      .value;

    loginMessage.className = "message";

    if (!username || !password) {
      loginMessage.textContent =
        "Username dan password wajib diisi.";

      loginMessage.classList.add("error");
      return;
    }

    try {
      const response = await fetch("/api/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        credentials: "include",
        body: JSON.stringify({
          username,
          password
        })
      });

      const data = await response.json();

      if (!response.ok) {
        loginMessage.textContent = data.message;
        loginMessage.classList.add("error");
        return;
      }

      loginMessage.textContent = "Login berhasil! 🎉";
      loginMessage.classList.add("success");

      setTimeout(() => {
        window.location.href = "/dashboard";
      }, 300);
    } catch {
      loginMessage.textContent =
        "Tidak dapat terhubung ke server.";

      loginMessage.classList.add("error");
    }
  });
}
