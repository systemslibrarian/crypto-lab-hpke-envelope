/* `?raw` imports, for tests that read a file's text rather than its exports.
 *
 * Vite resolves these at build time; this repository does not pull in
 * `vite/client`'s ambient types, so declare the one form used here. */
declare module '*?raw' {
  const contents: string;
  export default contents;
}
