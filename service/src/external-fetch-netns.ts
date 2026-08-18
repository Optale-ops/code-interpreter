import { spawnSync } from 'node:child_process';

/**
 * Whether this host lets an unprivileged process own a private network
 * namespace, which the real-boundary fixtures need: they bind the test address
 * on their own loopback and run a DNS authority and TLS origin inside it.
 *
 * Ubuntu 24.04 hosts (GitHub's `ubuntu-latest` among them) ship
 * `kernel.apparmor_restrict_unprivileged_userns=1`, which denies
 * `unshare --user`, so the fixtures cannot run there at all. Probing beats
 * assuming: the tests that need it skip loudly instead of reporting a boundary
 * failure that never happened, and still run wherever the capability exists
 * (developer boxes and the Docker real-boundary matrix, which is where the
 * R76 §8 deny matrix is actually proven).
 */
export function privateNetnsAvailable(): boolean {
  try {
    const probe = spawnSync('unshare', ['--user', '--map-root-user', '--net', 'true'], {
      stdio: 'ignore',
    });
    return probe.status === 0;
  } catch {
    return false;
  }
}
