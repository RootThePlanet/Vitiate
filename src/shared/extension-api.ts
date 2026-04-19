type ExtensionApi = typeof chrome;

const globalWithBrowser = globalThis as typeof globalThis & {
  browser?: ExtensionApi;
};

export const extensionApi: ExtensionApi = globalWithBrowser.browser ?? chrome;
