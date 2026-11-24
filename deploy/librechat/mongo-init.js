const appUser = process.env.LIBRECHAT_DB_USER;
const appPassword = process.env.LIBRECHAT_DB_PASSWORD;
if (!appUser || !appPassword) {
  throw new Error("LibreChat database credentials are missing");
}
db.getSiblingDB("LibreChat").createUser({
  user: appUser,
  pwd: appPassword,
  roles: [{ role: "readWrite", db: "LibreChat" }],
});