// A static export that lives under a base path (GitHub Pages serves this app at /food-safety-followup/) does not add
// the base path to a plain asset address or a link built by hand, so the browser would ask at the site root and get a 404.
// NEXT_PUBLIC_BASE_PATH is set only for that build; everywhere else the address is unchanged.
export const assetPath = (path) => `${process.env.NEXT_PUBLIC_BASE_PATH || ''}${path}`;
