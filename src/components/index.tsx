export interface WebKernelJsonLdProps {
  schema: Record<string, any> | Array<Record<string, any>>;
  id?: string;
}

/**
 * React Server Component for safe JSON-LD Schema.org injection.
 * Supports Search Engine & Answer Engine (AEO / GEO) optimization.
 */
export function WebKernelJsonLd({ schema, id }: WebKernelJsonLdProps) {
  if (!schema) return null;

  // Sanitize to prevent XSS breakout
  const jsonString = JSON.stringify(schema).replace(/</g, '\\u003c');

  return (
    <script
      id={id || 'webkernelai-jsonld'}
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: jsonString }}
    />
  );
}
