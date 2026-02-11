
  # Client Assertion and DPoP Generator

  This is a code bundle for Client Assertion and DPoP Generator. The original project is available at https://www.figma.com/design/FepWunwHRBky3DwnK6MlUw/Client-Assertion-and-DPoP-Generator.

  ## Running the code

  Run `npm i` to install the dependencies.

  Run `npm run dev` to start the development server.
  

## Deploy to GitHub Pages

1. Create a new GitHub repo and push this project (default branch: `main`).
2. In GitHub, go to **Settings → Pages**.
3. Under **Build and deployment**, set **Source** to **GitHub Actions**.
4. Push to `main` (or run the workflow manually). The site will build to `dist/` and deploy automatically.

### Local build

```bash
npm ci
npm run build
npm run preview
```
