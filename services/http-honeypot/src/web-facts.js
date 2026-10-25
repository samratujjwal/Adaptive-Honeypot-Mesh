export const WEB_FACTS = {
  companyName: "ExampleCorp",
  tagline: "A fictional company site for demonstration",
  wordpressVersion: "6.4.3",
  dbName: "example_wp_db",
  dbUser: "example_wp_user",
  dbHost: "localhost",
  users: [
    { username: "admin", displayName: "Site Admin", role: "administrator", email: "admin@example.com" },
    { username: "editor", displayName: "Ed Editor", role: "editor", email: "editor@example.com" },
    { username: "author", displayName: "Ann Author", role: "author", email: "author@example.com" },
  ],
  plugins: [
    { name: "Example Contact Form", version: "1.2.3", status: "active" },
    { name: "Example SEO Helper", version: "2.0.1", status: "active" },
    { name: "Example Cache", version: "1.0.0", status: "inactive" },
  ],
  posts: 12,
  comments: 34,
};

/**
 * Return a fresh copy of the fictional web facts.
 *
 * @returns {object} web facts
 */
export function getWebFacts() {
  return JSON.parse(JSON.stringify(WEB_FACTS));
}
