const globalWithBrowser = globalThis;
const extensionApi = globalWithBrowser.browser ?? chrome;

export { extensionApi as e };
