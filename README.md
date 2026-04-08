# Secure Harbour Starter Website

A lightweight Azure Static Web Apps starter for Secure Harbour.

## What is included

- Public website: Home, About, Services, Contact, Thank You
- Private owner dashboard at `/owner-portal`
- Owner login helper page at `/owner-login`
- Azure Functions API for:
  - query submission
  - query listing
  - query counts
  - query status updates
  - signed-in user info
- Cosmos DB integration for storing leads
- Static Web Apps route protection with a custom `owner` role

## Recommended Azure setup

1. Create an Azure Static Web Apps resource.
2. Deploy this repo with app location `/` and API location `/api`.
3. Create an Azure Cosmos DB for NoSQL account.
4. Create a database named `secureharbour`.
5. Create a container named `queries` with partition key `/id`.
6. Add these application settings in Static Web Apps:
   - `COSMOS_ENDPOINT`
   - `COSMOS_KEY`
   - `COSMOS_DATABASE_NAME=secureharbour`
   - `COSMOS_CONTAINER_NAME=queries`
7. Assign yourself the custom `owner` role in Static Web Apps.

## Role assignment

Static Web Apps supports custom roles through invitations. You can generate an invitation link from Azure CLI and assign the `owner` role.

Example:

```bash
az staticwebapp users invite \
  --name <your-static-web-app-name> \
  --resource-group <your-resource-group> \
  --authentication-provider AAD \
  --user-details <your-email-address> \
  --roles owner \
  --domain <your-app-domain>
```

Use `GitHub` instead of `AAD` if you want GitHub login.

## Login URLs

- Microsoft login: `/login/aad`
- GitHub login: `/login/github`
- Logout: `/logout`
- Owner helper page: `/owner-login`
- Owner dashboard: `/owner-portal`

## Local development

For the static pages only, you can use any simple web server.

For the full experience with APIs and auth, use Azure Static Web Apps CLI.

Install CLI:

```bash
npm install -g @azure/static-web-apps-cli
```

Start locally from the project root:

```bash
swa start . --api-location api
```

## Notes

- Public query submission is open.
- Owner dashboard APIs are protected by route rules and by server-side role checks.
- The owner route is intentionally not linked from the public website.
- This starter uses key-based Cosmos DB auth for launch speed. Later, move to managed identity and Cosmos DB RBAC.
