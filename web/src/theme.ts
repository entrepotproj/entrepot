import { createTheme, type MantineColorsTuple } from '@mantine/core';

const brand: MantineColorsTuple = [
  '#e7f3ff',
  '#d0e3ff',
  '#a1c4fa',
  '#6ea4f5',
  '#4488f1',
  '#2977ef',
  '#186eef',
  '#055dd5',
  '#0053c0',
  '#0047aa',
];

export const theme = createTheme({
  primaryColor: 'brand',
  colors: { brand },
  defaultRadius: 'md',
  fontFamily:
    'Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
  fontFamilyMonospace: 'ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Consolas, monospace',
  headings: { fontWeight: '650' },
  components: {
    Table: { defaultProps: { highlightOnHover: true, verticalSpacing: 'sm' } },
    Paper: { defaultProps: { withBorder: true, radius: 'md' } },
    Card: { defaultProps: { withBorder: true, radius: 'md' } },
    Tooltip: { defaultProps: { openDelay: 200 } },
  },
});
