function newSessionId() {
  return "sess-" + Math.random().toString(36).slice(2);
}
