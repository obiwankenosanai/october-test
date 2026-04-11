const ROLE_HIERARCHY = {
  admin: 3,
  editor: 2,
  viewer: 1,
};

function requireRole(role) {
  const requiredLevel = ROLE_HIERARCHY[role];

  if (requiredLevel === undefined) {
    throw new Error(`Unknown role: ${role}`);
  }

  return function (req, res, next) {
    const user = req.user;

    if (!user || !user.role) {
      return res.status(403).json({ error: 'Forbidden: no user or role present' });
    }

    const userLevel = ROLE_HIERARCHY[user.role];

    if (userLevel === undefined) {
      return res.status(403).json({ error: `Forbidden: unknown role '${user.role}'` });
    }

    if (userLevel < requiredLevel) {
      return res.status(403).json({ error: `Forbidden: requires '${role}' role or higher` });
    }

    next();
  };
}

module.exports = { requireRole, ROLE_HIERARCHY };
