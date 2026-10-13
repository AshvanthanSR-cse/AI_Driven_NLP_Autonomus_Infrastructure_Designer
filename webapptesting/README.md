# kintsugi-demo-site

A tiny front-end-only website (HTML/CSS/JS) packaged with nginx, used to test
Kintsugi's `ecs_fargate_service` recipe (Acceptance test 3).

- `Dockerfile` – nginx:alpine serving `site/` on port 80
- `site/` – the static website

Local test (optional): `docker build -t kintsugi-demo-site .` then
`docker run --rm -p 8080:80 kintsugi-demo-site` and open http://localhost:8080
