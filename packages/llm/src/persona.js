/**
 * Build the persona object for the honeypot terminal. Defaults
 * match the Day 3 seed; hostname comes from config.
 *
 * @param {string} hostname
 * @returns {{ id: string, hostname: string, os: string, kernel: string, role: string }}
 */
export function makePersona(hostname) {
  return {
    id: "ubuntu-2204",
    hostname: hostname || "srv-web-01",
    os: "Ubuntu 22.04.3 LTS",
    kernel: "5.15.0-91-generic",
    role: "web server",
  };
}
