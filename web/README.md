# Policy Engine Web UI

A React + TypeScript web interface for the Policy Engine GraphQL API.

## Prerequisites

- Node.js 18+ and npm (or pnpm/yarn)
- Policy Engine server running on port 8080

## Setup

```bash
# Install dependencies
npm install

# Generate GraphQL types (requires server running)
npm run codegen

# Start development server
npm run dev
```

The development server runs on http://localhost:3000 and proxies GraphQL requests to http://localhost:8080.

## Features

- **Status Dashboard**: View server status, version, and uptime
- **Interface Management**: Attach/detach XDP programs to network interfaces
- **Policy Rules**: Add, view, and delete policy rules
- **Statistics**: Real-time statistics for attached interfaces

## GraphQL Code Generation

This project uses `@graphql-codegen` to generate TypeScript types from the GraphQL schema.

```bash
# Generate once
npm run codegen

# Watch mode (regenerates on changes)
npm run codegen:watch
```

Generated files are placed in `src/gql/`.

## Building for Production

```bash
npm run build
```

Output is placed in `dist/`.

## Project Structure

```
web/
├── src/
│   ├── components/       # React components
│   │   ├── StatusCard.tsx
│   │   ├── InterfaceList.tsx
│   │   ├── RulesList.tsx
│   │   └── StatsPanel.tsx
│   ├── graphql/          # GraphQL operations
│   │   └── operations.graphql
│   ├── gql/              # Generated types (gitignored)
│   ├── App.tsx           # Main application
│   ├── main.tsx          # Entry point
│   └── index.css         # Global styles (Tailwind)
├── codegen.ts            # GraphQL codegen config
├── package.json
├── tailwind.config.js
├── tsconfig.json
└── vite.config.ts
```

## API Endpoints

When running the Policy Engine server:

- GraphQL API: http://localhost:8080/graphql
- GraphQL Playground: http://localhost:8080/playground
- Schema SDL: http://localhost:8080/schema.graphql
- Health Check: http://localhost:8080/health
