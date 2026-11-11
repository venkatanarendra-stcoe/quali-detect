/**
 * Data access for Root Console identity (platform users are a separate store from tenant users).
 * @param {{ db: any }} deps
 */
export function createPlatformIdentityRepository({ db }) {
  return Object.freeze({
    /** @param {{ platformUserId: string, at: Date }} input */
    touchLastLogin: ({ platformUserId, at }) =>
      db.platformUser.update({ where: { id: platformUserId }, data: { lastLoginAt: at } }),
    /** @param {{ platformUserId: string }} input */
    findPlatformUser: ({ platformUserId }) =>
      db.platformUser.findUnique({
        where: { id: platformUserId },
        select: { id: true, email: true, name: true, status: true },
      }),
  });
}
