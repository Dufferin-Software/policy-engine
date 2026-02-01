// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

import type { CodegenConfig } from '@graphql-codegen/cli'

const config: CodegenConfig = {
  // Fetch schema from running server or use local SDL file
  schema: process.env.GRAPHQL_SCHEMA_URL || './schema.graphql',
  // Scan component files for inline gql queries.
  // Exclude feature-flagged components (suricata/ipfix) whose GraphQL fields are
  // only present in builds compiled with those Cargo features — they are not in
  // the standard schema export and would otherwise fail document validation.
  documents: [
    'src/**/*.tsx',
    'src/**/*.ts',
    '!src/graphql/**/*.graphql',
    '!src/components/InspectPanel.tsx',
    '!src/components/FlowExportPanel.tsx',
  ],
  ignoreNoDocuments: true,
  generates: {
    './src/gql/': {
      preset: 'client',
      presetConfig: {
        gqlTagName: 'gql',
      },
      config: {
        scalars: {
          DateTime: 'string',
        },
      },
    },
    './src/gql/hooks.ts': {
      plugins: [
        'typescript',
        'typescript-operations',
        'typescript-react-apollo',
      ],
      config: {
        withHooks: true,
        withComponent: false,
        withHOC: false,
        scalars: {
          DateTime: 'string',
        },
      },
    },
  },
}

export default config
