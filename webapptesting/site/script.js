let clicks = 0;
document.getElementById("time").textContent = new Date().toLocaleString();
document.getElementById("btn").addEventListener("click", () => {
  clicks += 1;
  document.getElementById("msg").textContent =
    `The front end works! You clicked ${clicks} time${clicks === 1 ? "" : "s"}.`;
});
