function safeRedirectHost(value) {
  if (!value) return null;
  try {
    return new URL(value).host;
  } catch {
    return null;
  }
}

module.exports = function requestLog(req, res, next) {
  const started = Date.now();
  res.on("finish", () => {
    const redirectHost = safeRedirectHost(res.getHeader("location"));
    const suffix = redirectHost ? ` redirect=${redirectHost}/...` : "";
    console.log(
      `${req.method} ${req.path} -> ${res.statusCode} ${Date.now() - started}ms${suffix}`
    );
  });
  next();
};
